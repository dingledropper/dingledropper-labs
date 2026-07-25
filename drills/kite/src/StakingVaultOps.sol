// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {IStakingVault} from "../interfaces/IStakingVault.sol";
import {IStakingVaultOperations} from "../interfaces/IStakingVaultOperations.sol";
import {StakingVaultStorageLib} from "./StakingVaultStorage.sol";
import {StakingVaultInternals} from "./StakingVaultInternals.sol";
import {IKiteStakingManager} from "gokite-contracts/contracts/validator-manager/interfaces/IKiteStakingManager.sol";
import {PoSValidatorInfo} from "gokite-contracts/contracts/validator-manager/interfaces/IStakingManager.sol";
import {PChainOwner} from "gokite-contracts/contracts/validator-manager/interfaces/IACP99Manager.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title StakingVaultOperations
 * @notice Extension contract for StakingVault containing operations logic
 * @dev Called via delegatecall from StakingVault - operates on main contract's storage.
 *      NO constructor, NO initializer, NO storage variables - pure logic only.
 *      All state reads/writes go through StakingVaultStorageLib.
 *
 * IMPORTANT: This contract is NOT standalone. It must only be called via delegatecall
 * from StakingVault. Direct calls will fail or produce incorrect results.
 */
contract StakingVaultOperations is IStakingVaultOperations {
    using StakingVaultStorageLib for *;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ============================================
    // Modifiers
    // ============================================

    modifier nonReentrant() {
        StakingVaultStorageLib._nonReentrantBefore();
        _;
        StakingVaultStorageLib._nonReentrantAfter();
    }

    modifier onlyVaultAdmin() {
        // In delegatecall context, address(this) is the proxy (StakingVault)
        if (!IAccessControl(address(this)).hasRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE, msg.sender)) {
            revert IAccessControl.AccessControlUnauthorizedAccount(msg.sender, StakingVaultStorageLib.VAULT_ADMIN_ROLE);
        }
        _;
    }

    modifier onlyOperatorManager() {
        _checkOperatorManager();
        _;
    }

    modifier onlyOperator() {
        _checkOperator();
        _;
    }

    function _checkOperatorManager() internal view {
        // In delegatecall context, address(this) is the proxy (StakingVault)
        if (!IAccessControl(address(this)).hasRole(StakingVaultStorageLib.OPERATOR_MANAGER_ROLE, msg.sender)) {
            revert IStakingVault.StakingVault__NotOperatorManager(msg.sender);
        }
    }

    function _checkOperator() internal view {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (!$.operators[msg.sender].active) {
            revert IStakingVault.StakingVault__NotOperator(msg.sender);
        }
    }

    // ============================================
    // Validator Lifecycle
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint256 amount
    ) external nonReentrant onlyOperator returns (bytes32 validationID) {
        if (amount == 0) revert IStakingVault.StakingVault__InvalidAmount();

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if (amount > $.maximumValidatorStake) {
            revert IStakingVault.StakingVault__StakeExceedsMaximum(amount, $.maximumValidatorStake);
        }

        _checkDebtFreeze(msg.sender);

        if ($.operatorValidators[msg.sender].length() >= $.maxValidatorsPerOperator) {
            revert IStakingVault.StakingVault__LimitExceeded();
        }

        _checkBufferAndAllocation($, amount);

        uint64 minStakeDuration = StakingVaultInternals.getMinimumStakeDuration();
        uint16 delegationFeeBips = uint16($.operatorFeeBips);

        $.vaultAccountedBalance -= amount;
        validationID = $.stakingManager.initiateValidatorRegistration{value: amount}(
            nodeID,
            blsPublicKey,
            remainingBalanceOwner,
            disableOwner,
            delegationFeeBips,
            minStakeDuration,
            address(this)
        );

        $.validatorToOperator[validationID] = msg.sender;
        $.operatorValidators[msg.sender].add(validationID);
        $.validatorPrincipal[validationID] = amount;

        $.totalValidatorStake += amount;

        $.operators[msg.sender].activeStake += amount;

        emit IStakingVaultOperations.StakingVault__ValidatorRegistrationInitiated(msg.sender, validationID);
    }

    /// @inheritdoc IStakingVaultOperations
    function completeValidatorRegistration(
        uint32 messageIndex
    ) external nonReentrant returns (bytes32 validationID) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        validationID = $.stakingManager.completeValidatorRegistration(messageIndex);
        emit IStakingVaultOperations.StakingVault__ValidatorRegistrationCompleted(validationID);
    }

    /// @inheritdoc IStakingVaultOperations
    function initiateValidatorRemoval(
        bytes32 validationID
    ) external nonReentrant onlyOperator {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if ($.validatorToOperator[validationID] != msg.sender) {
            revert IStakingVault.StakingVault__ValidatorNotOwnedByOperator(validationID, msg.sender);
        }

        if ($.validatorPendingRemoval[validationID]) {
            revert IStakingVault.StakingVault__ValidatorPendingRemoval(validationID);
        }

        $.validatorPendingRemoval[validationID] = true;

        $.stakingManager.forceInitiateValidatorRemoval(validationID, false, 0);

        uint256 stakeAmount = $.validatorPrincipal[validationID];
        _recordRemovalInFlight($, msg.sender, validationID, stakeAmount, false);

        emit IStakingVaultOperations.StakingVault__ValidatorRemovalInitiated(msg.sender, validationID);
        emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
    }

    /// @inheritdoc IStakingVaultOperations
    function completeValidatorRemoval(
        uint32 messageIndex
    ) external nonReentrant returns (bytes32 validationID) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 balBefore = address(this).balance;
        $.isReceivingManagerFunds = true;
        validationID = $.stakingManager.completeValidatorRemoval(messageIndex);
        $.isReceivingManagerFunds = false;
        uint256 actualInflow = address(this).balance - balBefore;

        // SM's completeValidatorRemoval is permissionless — verify the returned validator belongs to this vault
        if ($.validatorToOperator[validationID] == address(0)) {
            revert IStakingVault.StakingVault__ValidatorNotFound(validationID);
        }

        uint256 stakeAmount = $.validatorPrincipal[validationID];
        $.vaultAccountedBalance += actualInflow;

        address operatorCache = $.validatorToOperator[validationID];
        _syncValidatorState($, validationID, stakeAmount);

        uint256 rewards = actualInflow > stakeAmount ? actualInflow - stakeAmount : 0;
        if (rewards > 0) {
            _splitRemovalRewards($, operatorCache, rewards);
        }

        emit IStakingVaultOperations.StakingVault__ValidatorRemovalCompleted(validationID, stakeAmount, rewards);
    }

    /// @inheritdoc IStakingVaultOperations
    function forceRemoveValidator(
        bytes32 validationID
    ) external nonReentrant onlyVaultAdmin {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        address operatorAddr = $.validatorToOperator[validationID];
        if (operatorAddr == address(0)) {
            revert IStakingVault.StakingVault__ValidatorNotFound(validationID);
        }

        if ($.validatorPendingRemoval[validationID]) {
            revert IStakingVault.StakingVault__ValidatorPendingRemoval(validationID);
        }
        $.validatorPendingRemoval[validationID] = true;

        emit IStakingVaultOperations.StakingVault__ValidatorRemovalInitiated(operatorAddr, validationID);

        $.stakingManager.forceInitiateValidatorRemoval(validationID, false, 0);

        uint256 stakeAmount = $.validatorPrincipal[validationID];
        _recordRemovalInFlight($, operatorAddr, validationID, stakeAmount, false);

        emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
    }

    // ============================================
    // Delegator Lifecycle
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function initiateDelegatorRegistration(
        bytes32 validationID,
        uint256 amount
    ) external nonReentrant onlyOperator returns (bytes32 delegationID) {
        if (amount == 0) revert IStakingVault.StakingVault__InvalidAmount();

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if (amount > $.maximumDelegatorStake) {
            revert IStakingVault.StakingVault__StakeExceedsMaximum(amount, $.maximumDelegatorStake);
        }

        _checkDebtFreeze(msg.sender);

        bool isVaultOwned = $.validatorToOperator[validationID] != address(0);

        if (isVaultOwned) {
            if ($.validatorPendingRemoval[validationID]) {
                revert IStakingVault.StakingVault__ValidatorPendingRemoval(validationID);
            }
        } else {
            PoSValidatorInfo memory validatorInfo = _getStakingValidatorInfo(validationID);

            if (validatorInfo.owner == address(0)) {
                revert IStakingVault.StakingVault__ExternalValidatorNotFound(validationID);
            }

            if (validatorInfo.delegationFeeBips > uint16($.operatorFeeBips)) {
                revert IStakingVault.StakingVault__DelegationFeeTooHigh(
                    validatorInfo.delegationFeeBips, uint16($.operatorFeeBips)
                );
            }

            // Reject if delegationFee + MAX_PROTOCOL_FEE > 100%
            if (
                uint256(validatorInfo.delegationFeeBips) + StakingVaultStorageLib.MAX_PROTOCOL_FEE_BIPS
                    > StakingVaultStorageLib.BIPS_DENOMINATOR
            ) {
                revert IStakingVault.StakingVault__DelegationFeeTooHigh(
                    validatorInfo.delegationFeeBips,
                    uint16(StakingVaultStorageLib.BIPS_DENOMINATOR - StakingVaultStorageLib.MAX_PROTOCOL_FEE_BIPS)
                );
            }

            uint64 requiredDuration = StakingVaultInternals.getMinimumStakeDuration();
            if (validatorInfo.minStakeDuration != requiredDuration) {
                revert IStakingVault.StakingVault__MinStakeDurationMismatch(
                    validatorInfo.minStakeDuration, requiredDuration
                );
            }
        }

        _checkBufferAndAllocation($, amount);

        $.vaultAccountedBalance -= amount;
        delegationID = $.stakingManager.initiateDelegatorRegistration{value: amount}(validationID, address(this));

        $.delegatorInfo[delegationID] = IStakingVault.DelegatorInfo({
            validationID: validationID, operator: msg.sender, isVaultOwnedValidator: isVaultOwned
        });

        $.operatorDelegations[msg.sender].add(delegationID);
        $.delegationPrincipal[delegationID] = amount;

        $.operators[msg.sender].activeStake += amount;
        $.totalDelegatedStake += amount;

        emit IStakingVaultOperations.StakingVault__DelegatorRegistrationInitiated(
            msg.sender, validationID, delegationID, amount
        );
    }

    /// @inheritdoc IStakingVaultOperations
    function completeDelegatorRegistration(
        bytes32 delegationID,
        uint32 messageIndex,
        uint32 uptimeMessageIndex
    ) external nonReentrant {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if ($.delegatorInfo[delegationID].operator == address(0)) {
            revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        }

        uint256 balBefore = address(this).balance;
        $.isReceivingManagerFunds = true;
        $.stakingManager.completeDelegatorRegistration(delegationID, messageIndex, uptimeMessageIndex);
        $.isReceivingManagerFunds = false;
        uint256 inflow = address(this).balance - balBefore;

        (bool smOk, uint8 status, uint256 smAmount,) = StakingVaultInternals.getDelegatorFullInfo(delegationID);
        if (smOk && status == 0 && smAmount == 0) {
            uint256 principal = $.delegationPrincipal[delegationID];
            $.vaultAccountedBalance += inflow;
            _syncDelegatorState($, delegationID, principal);
            emit IStakingVaultOperations.StakingVault__DelegatorRegistrationAborted(delegationID, principal);
            return;
        }

        $.vaultAccountedBalance += inflow;
        emit IStakingVaultOperations.StakingVault__DelegatorRegistrationCompleted(
            $.delegatorInfo[delegationID].operator, delegationID
        );
    }

    /// @inheritdoc IStakingVaultOperations
    function initiateDelegatorRemoval(
        bytes32 delegationID
    ) external nonReentrant {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        IStakingVault.DelegatorInfo storage info = $.delegatorInfo[delegationID];

        if (info.operator == address(0)) {
            revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        }

        if (msg.sender != info.operator && !IAccessControl(address(this)).hasRole(bytes32(0), msg.sender)) {
            revert IStakingVault.StakingVault__NotDelegatorOperator(delegationID, msg.sender);
        }

        (bool smSuccess, uint8 smStatus,,) = StakingVaultInternals.getDelegatorFullInfo(delegationID);
        if (!smSuccess) revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        if (smStatus == 1) revert IStakingVault.StakingVault__DelegatorIncomplete(delegationID);
        if (smStatus == 3) revert IStakingVault.StakingVault__DelegatorAlreadyPendingRemoval(delegationID);
        if (smStatus != 2) revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);

        uint256 amount = $.delegationPrincipal[delegationID];

        uint256 balBefore = address(this).balance;
        $.isReceivingManagerFunds = true;
        $.stakingManager.forceInitiateDelegatorRemoval(delegationID, false, 0);
        $.isReceivingManagerFunds = false;
        uint256 actualInflow = address(this).balance - balBefore;

        address operatorAddr = info.operator;

        if (actualInflow > 0) {
            // Synchronous completion — parent validator already ended
            $.vaultAccountedBalance += actualInflow;
            uint256 rewards = actualInflow > amount ? actualInflow - amount : 0;
            IStakingVault.DelegatorInfo memory infoCache = IStakingVault.DelegatorInfo({
                operator: info.operator,
                validationID: info.validationID,
                isVaultOwnedValidator: info.isVaultOwnedValidator
            });
            _syncDelegatorState($, delegationID, amount);
            if (rewards > 0) {
                _splitDelegatorRemovalRewards($, infoCache, rewards);
            }
            emit IStakingVaultOperations.StakingVault__DelegatorRemovalCompleted(delegationID, amount, rewards);
        } else {
            _recordRemovalInFlight($, operatorAddr, delegationID, amount, true);
            emit IStakingVaultOperations.StakingVault__DelegatorRemovalInitiated(operatorAddr, delegationID);
            emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
        }
    }

    /// @inheritdoc IStakingVaultOperations
    function completeDelegatorRemoval(
        bytes32 delegationID,
        uint32 messageIndex
    ) external nonReentrant {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        IStakingVault.DelegatorInfo storage info = $.delegatorInfo[delegationID];
        if (info.operator == address(0)) {
            revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        }

        uint256 amount = $.delegationPrincipal[delegationID];
        if (amount == 0) revert IStakingVault.StakingVault__DelegatorNotFound(delegationID); // guard: principal cleared means already completed

        // H2: Adopt externally-initiated removal we haven't tracked
        if ($.delegatorRemovalInitiatedEpoch[delegationID] == 0) {
            _recordRemovalInFlight($, info.operator, delegationID, amount, true);
            emit IStakingVaultOperations.StakingVault__DelegatorRemovalAdopted(info.operator, delegationID, amount);
        }

        uint256 balBefore = address(this).balance;
        $.isReceivingManagerFunds = true;
        $.stakingManager.completeDelegatorRemoval(delegationID, messageIndex);
        $.isReceivingManagerFunds = false;
        uint256 actualInflow = address(this).balance - balBefore;

        $.vaultAccountedBalance += actualInflow;

        uint256 rewards = actualInflow > amount ? actualInflow - amount : 0;
        IStakingVault.DelegatorInfo memory infoCache = IStakingVault.DelegatorInfo({
            operator: info.operator, validationID: info.validationID, isVaultOwnedValidator: info.isVaultOwnedValidator
        });
        _syncDelegatorState($, delegationID, amount);
        if (rewards > 0) {
            _splitDelegatorRemovalRewards($, infoCache, rewards);
        }

        emit IStakingVaultOperations.StakingVault__DelegatorRemovalCompleted(delegationID, amount, rewards);
    }

    /// @inheritdoc IStakingVaultOperations
    function forceRemoveDelegator(
        bytes32 delegationID
    ) external nonReentrant onlyVaultAdmin {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        IStakingVault.DelegatorInfo storage info = $.delegatorInfo[delegationID];
        if (info.operator == address(0)) {
            revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        }

        (bool smSuccess, uint8 smStatus,,) = StakingVaultInternals.getDelegatorFullInfo(delegationID);
        if (!smSuccess) revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);
        if (smStatus == 1) revert IStakingVault.StakingVault__DelegatorIncomplete(delegationID);
        if (smStatus == 3) revert IStakingVault.StakingVault__DelegatorAlreadyPendingRemoval(delegationID);
        if (smStatus != 2) revert IStakingVault.StakingVault__DelegatorNotFound(delegationID);

        uint256 amount = $.delegationPrincipal[delegationID];

        uint256 balBefore = address(this).balance;
        $.isReceivingManagerFunds = true;
        $.stakingManager.forceInitiateDelegatorRemoval(delegationID, false, 0);
        $.isReceivingManagerFunds = false;
        uint256 actualInflow = address(this).balance - balBefore;

        address operatorAddr = info.operator;

        if (actualInflow > 0) {
            // Synchronous completion — parent validator already ended
            $.vaultAccountedBalance += actualInflow;
            uint256 rewards = actualInflow > amount ? actualInflow - amount : 0;
            IStakingVault.DelegatorInfo memory infoCache = IStakingVault.DelegatorInfo({
                operator: info.operator,
                validationID: info.validationID,
                isVaultOwnedValidator: info.isVaultOwnedValidator
            });
            _syncDelegatorState($, delegationID, amount);
            if (rewards > 0) {
                _splitDelegatorRemovalRewards($, infoCache, rewards);
            }
            emit IStakingVaultOperations.StakingVault__DelegatorRemovalCompleted(delegationID, amount, rewards);
        } else {
            emit IStakingVaultOperations.StakingVault__DelegatorRemovalInitiated(operatorAddr, delegationID);
            _recordRemovalInFlight($, operatorAddr, delegationID, amount, true);
            emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
        }
    }

    // ============================================
    // Liquidity Management
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function prepareWithdrawals() external nonReentrant {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 currentEpoch = StakingVaultInternals.getCurrentEpoch();
        uint256 availableStake = StakingVaultInternals.getAvailableStake();

        uint256 pendingAmount;
        {
            uint256 totalPending = $.pendingWithdrawalStake;
            uint256 claimable = $.claimableWithdrawalStake;
            uint256 currentEpochAmount =
                ($.currentEpochWithdrawalEpoch == currentEpoch) ? $.currentEpochWithdrawalAmount : 0;
            uint256 deductions = claimable + currentEpochAmount;
            pendingAmount = totalPending > deductions ? totalPending - deductions : 0;
        }

        if (availableStake >= pendingAmount) return;

        uint256 amountToFree = pendingAmount - availableStake;
        uint256 removalsInitiated = _selectAndRemoveStake(amountToFree);

        emit IStakingVaultOperations.StakingVault__LiquidityPrepared(currentEpoch, removalsInitiated, amountToFree);
    }

    // ============================================
    // Harvesting
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function harvest() external nonReentrant returns (uint256 totalRewards) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        $.isReceivingManagerFunds = true;
        uint256 opLen = $.operatorSet.length();
        for (uint256 i; i < opLen;) {
            totalRewards += _harvestOperatorValidators($, i, 0, type(uint256).max);
            totalRewards += _harvestOperatorDelegators($, i, 0, type(uint256).max);
            unchecked {
                ++i;
            }
        }
        $.isReceivingManagerFunds = false;
    }

    /// @inheritdoc IStakingVaultOperations
    function harvestValidators(
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) external nonReentrant returns (uint256 totalRewards) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (operatorIndex >= $.operatorSet.length()) {
            revert IStakingVault.StakingVault__InvalidOperatorIndex(operatorIndex);
        }
        $.isReceivingManagerFunds = true;
        totalRewards = _harvestOperatorValidators($, operatorIndex, start, batchSize);
        $.isReceivingManagerFunds = false;
    }

    /// @inheritdoc IStakingVaultOperations
    function harvestDelegators(
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) external nonReentrant returns (uint256 totalRewards) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (operatorIndex >= $.operatorSet.length()) {
            revert IStakingVault.StakingVault__InvalidOperatorIndex(operatorIndex);
        }
        $.isReceivingManagerFunds = true;
        totalRewards = _harvestOperatorDelegators($, operatorIndex, start, batchSize);
        $.isReceivingManagerFunds = false;
    }

    // ============================================
    // Operator Management
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function addOperator(
        address operator,
        uint256 allocationBips,
        address feeRecipient
    ) external onlyOperatorManager {
        StakingVaultInternals.requireNonZero(operator);

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if ($.operatorSet.length() >= $.maxOperators) {
            revert IStakingVault.StakingVault__LimitExceeded();
        }
        if ($.operators[operator].active) {
            revert IStakingVault.StakingVault__OperatorAlreadyExists(operator);
        }

        uint256 totalAlloc = _getTotalAllocationBips() + allocationBips;
        if (totalAlloc > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert IStakingVault.StakingVault__AllocationExceeded(totalAlloc);
        }

        address recipient = feeRecipient == address(0) ? operator : feeRecipient;
        if (recipient == address(this)) revert IStakingVault.StakingVault__InvalidFeeRecipient();

        $.operators[operator] = IStakingVault.Operator({
            active: true, allocationBips: allocationBips, activeStake: 0, accruedFees: 0, feeRecipient: recipient
        });
        $.operatorSet.add(operator);

        emit IStakingVaultOperations.StakingVault__OperatorAdded(operator, allocationBips);
    }

    /// @inheritdoc IStakingVaultOperations
    function removeOperator(
        address operator
    ) external onlyOperatorManager {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        IStakingVault.Operator storage op = $.operators[operator];

        if (!op.active) revert IStakingVault.StakingVault__OperatorNotActive(operator);
        if ($.operatorValidators[operator].length() > 0) {
            revert IStakingVault.StakingVault__OperatorHasActiveValidators(operator);
        }
        if (op.activeStake > 0 || $.operatorDelegations[operator].length() > 0) {
            revert IStakingVault.StakingVault__OperatorHasDelegators(operator);
        }
        if (op.accruedFees > 0) revert IStakingVault.StakingVault__OperatorHasUnclaimedFees(operator);

        // Clean up exit debt (prevents corruption on re-addition)
        uint256 exitDebt = $.operatorExitDebt[operator];
        if (exitDebt > 0) {
            $.totalExitDebt -= exitDebt;
            delete $.operatorExitDebt[operator];
        }

        delete $.operatorPriorEpochPendingAmount[operator];
        delete $.operatorCurrentEpochPendingAmount[operator];

        // Sets are guaranteed empty by explicit length checks above (no delete needed for EnumerableSet)

        $.operatorSet.remove(operator);
        delete $.operators[operator];

        emit IStakingVaultOperations.StakingVault__OperatorRemoved(operator);
    }

    /// @inheritdoc IStakingVaultOperations
    function updateOperatorAllocations(
        address[] calldata operators,
        uint256[] calldata newBips
    ) external onlyOperatorManager {
        uint256 len = operators.length;
        if (len == 0 || len != newBips.length) revert IStakingVault.StakingVault__ArrayLengthMismatch();

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        for (uint256 i; i < len;) {
            address operator = operators[i];
            IStakingVault.Operator storage op = $.operators[operator];
            if (!op.active) revert IStakingVault.StakingVault__OperatorNotActive(operator);

            uint256 oldBips = op.allocationBips;
            op.allocationBips = newBips[i];
            emit IStakingVaultOperations.StakingVault__OperatorAllocationUpdated(operator, oldBips, newBips[i]);

            unchecked {
                ++i;
            }
        }

        uint256 totalAllocation = _getTotalAllocationBips();
        if (totalAllocation > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert IStakingVault.StakingVault__AllocationExceeded(totalAllocation);
        }
    }

    /// @inheritdoc IStakingVaultOperations
    /// @dev If feeRecipient reverts, the claim reverts -- but state is safe (accruedFees
    ///      not cleared). Operator can fix via setOperatorFeeRecipient() then retry.
    function claimOperatorFees() external nonReentrant {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        IStakingVault.Operator storage op = $.operators[msg.sender];

        uint256 fees = op.accruedFees;
        if (fees == 0) revert IStakingVault.StakingVault__NoFeesToClaim();

        $.totalAccruedOperatorFees -= fees;
        op.accruedFees = 0;
        $.vaultAccountedBalance -= fees;

        address recipient = op.feeRecipient != address(0) ? op.feeRecipient : msg.sender;
        StakingVaultInternals.sendValue(payable(recipient), fees);

        emit IStakingVaultOperations.StakingVault__OperatorFeesClaimed(msg.sender, fees);
    }

    /// @inheritdoc IStakingVaultOperations
    function forceClaimOperatorFees(
        address operator
    ) external nonReentrant onlyOperatorManager {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        IStakingVault.Operator storage op = $.operators[operator];

        if (!op.active) revert IStakingVault.StakingVault__OperatorNotActive(operator);

        uint256 fees = op.accruedFees;
        if (fees == 0) revert IStakingVault.StakingVault__NoFeesToClaim();

        $.totalAccruedOperatorFees -= fees;
        op.accruedFees = 0;
        $.vaultAccountedBalance -= fees;

        address recipient = op.feeRecipient != address(0) ? op.feeRecipient : operator;
        (bool success,) = payable(recipient).call{value: fees}("");
        if (success) {
            emit IStakingVaultOperations.StakingVault__OperatorFeesClaimed(operator, fees);
        } else {
            // Fees forfeit to pool — operator set a reverting recipient
            $.vaultAccountedBalance += fees;
            emit IStakingVaultOperations.StakingVault__OperatorFeesForfeited(operator, fees);
        }
    }

    /// @inheritdoc IStakingVaultOperations
    function setOperatorFeeRecipient(
        address feeRecipient
    ) external {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        IStakingVault.Operator storage op = $.operators[msg.sender];

        if (!op.active) revert IStakingVault.StakingVault__OperatorNotActive(msg.sender);
        if (feeRecipient == address(this)) revert IStakingVault.StakingVault__InvalidFeeRecipient();

        address oldRecipient = op.feeRecipient;
        op.feeRecipient = feeRecipient;
        emit IStakingVaultOperations.StakingVault__OperatorFeeRecipientUpdated(msg.sender, oldRecipient, feeRecipient);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Sync vault state after delegator removal (shared cleanup logic)
     * @dev Called by completeDelegatorRemoval and the synchronous-completion paths
     * @param $ Storage pointer
     * @param delegationID The delegation being removed
     * @param amount The stake amount to decrement
     */
    function _syncDelegatorState(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        bytes32 delegationID,
        uint256 amount
    ) internal {
        address operatorAddr = $.delegatorInfo[delegationID].operator;

        if (operatorAddr != address(0)) {
            if ($.operators[operatorAddr].activeStake >= amount) {
                $.operators[operatorAddr].activeStake -= amount;
            } else {
                emit IStakingVaultOperations.StakingVault__AccountingMismatchDetected(
                    "syncDelegatorActiveStake", amount, $.operators[operatorAddr].activeStake
                );
                $.operators[operatorAddr].activeStake = 0;
            }
        }

        if ($.totalDelegatedStake >= amount) {
            $.totalDelegatedStake -= amount;
        } else {
            emit IStakingVaultOperations.StakingVault__AccountingMismatchDetected(
                "syncDelegatorTotalStake", amount, $.totalDelegatedStake
            );
            $.totalDelegatedStake = 0;
        }

        _decrementInFlight($, operatorAddr, amount, $.delegatorRemovalInitiatedEpoch[delegationID]);
        delete $.delegatorRemovalInitiatedEpoch[delegationID];
        delete $.delegationPrincipal[delegationID];
        $.operatorDelegations[operatorAddr].remove(delegationID);
        delete $.delegatorInfo[delegationID];
    }

    /**
     * @notice Sync vault state after validator removal (shared cleanup logic)
     * @dev Called by completeValidatorRemoval to clean up validator state
     * @param $ Storage pointer
     * @param validationID The validator being removed
     * @param stakeAmount The stake amount to decrement
     */
    function _syncValidatorState(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        bytes32 validationID,
        uint256 stakeAmount
    ) internal {
        address operatorAddr = $.validatorToOperator[validationID];

        if ($.totalValidatorStake >= stakeAmount) {
            $.totalValidatorStake -= stakeAmount;
        } else {
            emit IStakingVaultOperations.StakingVault__AccountingMismatchDetected(
                "syncValidatorTotalStake", stakeAmount, $.totalValidatorStake
            );
            $.totalValidatorStake = 0;
        }

        _decrementInFlight($, operatorAddr, stakeAmount, $.validatorRemovalInitiatedEpoch[validationID]);
        delete $.validatorRemovalInitiatedEpoch[validationID];
        delete $.validatorPendingRemoval[validationID];
        delete $.validatorToOperator[validationID];
        delete $.validatorPrincipal[validationID];

        if (operatorAddr != address(0)) {
            IStakingVault.Operator storage op = $.operators[operatorAddr];
            if (op.activeStake >= stakeAmount) {
                op.activeStake -= stakeAmount;
            } else {
                emit IStakingVaultOperations.StakingVault__AccountingMismatchDetected(
                    "syncValidatorActiveStake", stakeAmount, op.activeStake
                );
                op.activeStake = 0;
            }
            $.operatorValidators[operatorAddr].remove(validationID);
        }
    }

    function _selectAndRemoveStake(
        uint256 amountNeeded
    ) internal returns (uint256 removalsInitiated) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        _reconcileEpochPending();

        StakingVaultStorageLib.RemovalContext memory ctx;
        ctx.effectiveNeeded = amountNeeded;
        if (ctx.effectiveNeeded == 0) return 0;

        uint256 opLen = $.operatorSet.length();
        if (opLen == 0) revert IStakingVault.StakingVault__NoEligibleStake();

        uint64 minDuration = StakingVaultInternals.getMinimumStakeDuration();
        ctx.maturityCutoff = uint64(block.timestamp) > minDuration ? uint64(block.timestamp) - minDuration : 0;

        ctx.activeOperators = new address[](opLen);
        ctx.targetShares = new uint256[](opLen);
        ctx.totalAllocationBips = _getTotalAllocationBips();

        // Single pass: collect active operators with stake, compute weights.
        // Weight floor of 1 ensures deprecated operators (allocationBips == 0, no debt)
        // are included but receive near-zero proportional targets.
        uint256 totalWeightNumerator;
        uint256[] memory weightNumerators = new uint256[](opLen);

        for (uint256 i; i < opLen;) {
            address operatorAddr = $.operatorSet.at(i);
            IStakingVault.Operator storage op = $.operators[operatorAddr];
            if (op.active && op.activeStake > 0) {
                ctx.activeOperators[ctx.activeCount] = operatorAddr;
                uint256 weight = (op.allocationBips * ctx.effectiveNeeded)
                    + ($.operatorExitDebt[operatorAddr] * StakingVaultStorageLib.BIPS_DENOMINATOR);
                weightNumerators[ctx.activeCount] = weight > 0 ? weight : 1;
                totalWeightNumerator += weightNumerators[ctx.activeCount];
                unchecked {
                    ++ctx.activeCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (ctx.activeCount == 0) revert IStakingVault.StakingVault__NoEligibleStake();

        // Compute proportional target shares
        {
            uint256 totalAllocated;
            for (uint256 i; i < ctx.activeCount;) {
                ctx.targetShares[i] = (ctx.effectiveNeeded * weightNumerators[i]) / totalWeightNumerator;
                totalAllocated += ctx.targetShares[i];
                unchecked {
                    ++i;
                }
            }
            // Distribute rounding dust only to operators with real weight (skip weight-floor operators).
            // A 1-wei target on a deprecated operator would trigger a full validator removal (~20+ ether),
            // which is disproportionate. Weight-floor operators intentionally get target = 0.
            for (uint256 i; i < ctx.activeCount && totalAllocated < ctx.effectiveNeeded;) {
                if (weightNumerators[i] > 1) {
                    ctx.targetShares[i] += 1;
                    unchecked {
                        ++totalAllocated;
                    }
                }
                unchecked {
                    ++i;
                }
            }
        }

        uint256[] memory contributions = new uint256[](ctx.activeCount);
        uint256 removalsThisCall;
        uint256 delegationScansThisCall;

        // Phase 1: Process delegations for all operators
        for (
            uint256 i;
            i < ctx.activeCount && removalsThisCall < StakingVaultStorageLib.MAX_REMOVALS_PER_CALL
                && delegationScansThisCall < StakingVaultStorageLib.MAX_DELEGATION_SCAN_PER_CALL;

        ) {
            address operatorAddr = ctx.activeOperators[i];
            uint256 pendingCredit =
                $.operatorPriorEpochPendingAmount[operatorAddr] + $.operatorCurrentEpochPendingAmount[operatorAddr];
            uint256 remainingTarget = ctx.targetShares[i] > pendingCredit ? ctx.targetShares[i] - pendingCredit : 0;
            uint256 operatorsLeft = ctx.activeCount - i;
            uint256 remainingGlobalBudget =
                StakingVaultStorageLib.MAX_DELEGATION_SCAN_PER_CALL - delegationScansThisCall;
            uint256 perOpScanBudget = remainingGlobalBudget / operatorsLeft;
            if (perOpScanBudget == 0) perOpScanBudget = 1;

            (uint256 contrib, uint256 removals, uint256 scans) = _processOperatorDelegationsForRemoval(
                $, operatorAddr, remainingTarget, ctx.maturityCutoff, removalsThisCall, perOpScanBudget
            );
            contributions[i] = contrib + pendingCredit;
            removalsThisCall += removals;
            delegationScansThisCall += scans;
            removalsInitiated += removals;
            unchecked {
                ++i;
            }
        }

        // Phase 2: Fallback to validators when delegations didn't meet target
        uint256 validatorScansThisCall;
        for (
            uint256 i;
            i < ctx.activeCount && removalsThisCall < StakingVaultStorageLib.MAX_REMOVALS_PER_CALL
                && validatorScansThisCall < StakingVaultStorageLib.MAX_VALIDATOR_SCAN_PER_CALL;

        ) {
            address operatorAddr = ctx.activeOperators[i];
            if (contributions[i] < ctx.targetShares[i]) {
                uint256 remainingTarget = ctx.targetShares[i] - contributions[i];
                uint256 operatorsLeft = ctx.activeCount - i;
                uint256 remainingGlobalBudget =
                    StakingVaultStorageLib.MAX_VALIDATOR_SCAN_PER_CALL - validatorScansThisCall;
                uint256 perOpValidatorScanBudget = remainingGlobalBudget / operatorsLeft;
                if (perOpValidatorScanBudget == 0) perOpValidatorScanBudget = 1;
                (uint256 valContrib, uint256 valRemovals, uint256 valScans) = _processOperatorValidatorsForRemoval(
                    $, operatorAddr, remainingTarget, ctx.maturityCutoff, removalsThisCall, perOpValidatorScanBudget
                );
                contributions[i] += valContrib;
                removalsThisCall += valRemovals;
                validatorScansThisCall += valScans;
                removalsInitiated += valRemovals;
            }
            unchecked {
                ++i;
            }
        }

        for (uint256 i; i < ctx.activeCount;) {
            address operatorAddr = ctx.activeOperators[i];
            uint256 baseShare = ctx.totalAllocationBips > 0
                ? (ctx.effectiveNeeded * $.operators[operatorAddr].allocationBips) / ctx.totalAllocationBips
                : 0;

            if (contributions[i] > baseShare) {
                uint256 paydown = contributions[i] - baseShare;
                uint256 currentDebt = $.operatorExitDebt[operatorAddr];
                uint256 reduction = paydown < currentDebt ? paydown : currentDebt;
                if (reduction > 0) {
                    $.operatorExitDebt[operatorAddr] -= reduction;
                    $.totalExitDebt -= reduction;
                    emit IStakingVaultOperations.StakingVault__ExitDebtReduced(
                        operatorAddr, reduction, $.operatorExitDebt[operatorAddr]
                    );
                }
            }
            if (contributions[i] < ctx.targetShares[i]) {
                uint256 shortfall = ctx.targetShares[i] - contributions[i];
                $.operatorExitDebt[operatorAddr] += shortfall;
                $.totalExitDebt += shortfall;
                emit IStakingVaultOperations.StakingVault__ExitDebtRecorded(
                    operatorAddr, shortfall, $.operatorExitDebt[operatorAddr]
                );
            }
            unchecked {
                ++i;
            }
        }

        if (removalsInitiated > 0) {
            emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
        } else {
            revert IStakingVault.StakingVault__NoEligibleStake();
        }
    }

    /// @dev Scan an operator's delegations and initiate removals to meet the target amount.
    function _processOperatorDelegationsForRemoval(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        address operatorAddr,
        uint256 remainingTarget,
        uint64 maturityCutoff,
        uint256 removalsThisCall,
        uint256 maxScans
    ) internal returns (uint256 contribution, uint256 removals, uint256 scans) {
        uint256 delLen = $.operatorDelegations[operatorAddr].length();
        for (uint256 j = delLen; j > 0 && contribution < remainingTarget;) {
            unchecked {
                --j;
            }
            if (removalsThisCall + removals >= StakingVaultStorageLib.MAX_REMOVALS_PER_CALL || scans >= maxScans) {
                break;
            }

            bytes32 delegationID = $.operatorDelegations[operatorAddr].at(j);

            // Skip vault-initiated pending removals without consuming scan budget
            if ($.delegatorRemovalInitiatedEpoch[delegationID] != 0) continue;

            unchecked {
                ++scans;
            }

            uint256 principal = $.delegationPrincipal[delegationID];

            if (principal == 0) continue;

            (bool smOk, uint8 status, uint256 smAmount, uint64 startTime) =
                StakingVaultInternals.getDelegatorFullInfo(delegationID);
            if (!smOk) continue;
            if (status == 3) {
                // Adopt externally-initiated PendingRemoved we haven't tracked
                _recordRemovalInFlight($, operatorAddr, delegationID, principal, true);
                contribution += principal;
                unchecked {
                    ++removals;
                }
                emit IStakingVaultOperations.StakingVault__DelegatorRemovalAdopted(
                    operatorAddr, delegationID, principal
                );
            } else if (status == 2 && startTime != 0 && startTime <= maturityCutoff && smAmount > 0) {
                // Active delegation, mature and live — initiate removal
                uint256 balBefore = address(this).balance;
                $.isReceivingManagerFunds = true;
                bool callOk = _callBool(
                    address($.stakingManager),
                    abi.encodeWithSelector(
                        StakingVaultStorageLib.SEL_FORCE_INITIATE_DELEGATOR_REMOVAL, delegationID, false, uint32(0)
                    )
                );
                $.isReceivingManagerFunds = false;
                uint256 actualInflow = address(this).balance - balBefore;

                if (callOk) {
                    if (actualInflow > 0) {
                        // Synchronous completion — parent validator already ended
                        $.vaultAccountedBalance += actualInflow;
                        uint256 rewards = actualInflow > principal ? actualInflow - principal : 0;
                        IStakingVault.DelegatorInfo memory infoCache = IStakingVault.DelegatorInfo({
                            operator: $.delegatorInfo[delegationID].operator,
                            validationID: $.delegatorInfo[delegationID].validationID,
                            isVaultOwnedValidator: $.delegatorInfo[delegationID].isVaultOwnedValidator
                        });
                        _syncDelegatorState($, delegationID, principal);
                        if (rewards > 0) {
                            _splitDelegatorRemovalRewards($, infoCache, rewards);
                        }
                        contribution += principal;
                        unchecked {
                            ++removals;
                        }
                        emit IStakingVaultOperations.StakingVault__DelegatorRemovalCompleted(
                            delegationID, principal, rewards
                        );
                    } else {
                        // Normal async initiation
                        _recordRemovalInFlight($, operatorAddr, delegationID, principal, true);
                        contribution += principal;
                        unchecked {
                            ++removals;
                        }
                        emit IStakingVaultOperations.StakingVault__DelegatorRemovalInitiated(operatorAddr, delegationID);
                    }
                } else {
                    emit IStakingVaultOperations.StakingVault__DelegatorRemovalFailed(delegationID, operatorAddr);
                }
            }
            // else: non-Active status (PendingAdded, PendingRemoved already tracked, Unknown) — skip
        }
    }

    /// @dev Scan an operator's validators and initiate removals to meet the target amount.
    function _processOperatorValidatorsForRemoval(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        address operatorAddr,
        uint256 remainingTarget,
        uint64 maturityCutoff,
        uint256 removalsThisCall,
        uint256 maxScans
    ) internal returns (uint256 contribution, uint256 removals, uint256 scans) {
        uint256 valLen = $.operatorValidators[operatorAddr].length();
        if (valLen == 0) return (0, 0, 0);

        address mgr = address($.stakingManager);

        // Iterate in reverse order (newest validators first)
        for (uint256 i = valLen; i > 0 && contribution < remainingTarget;) {
            unchecked {
                --i;
            }
            if (removalsThisCall + removals >= StakingVaultStorageLib.MAX_REMOVALS_PER_CALL || scans >= maxScans) {
                break;
            }
            unchecked {
                ++scans;
            }

            bytes32 validationID = $.operatorValidators[operatorAddr].at(i);

            if ($.validatorPendingRemoval[validationID]) continue;

            uint64 validatorStartTime = StakingVaultInternals.getValidatorStartTimeFromManager(validationID);
            if (validatorStartTime == 0 || validatorStartTime > maturityCutoff) continue;

            $.validatorPendingRemoval[validationID] = true;
            if (_callBool(
                    mgr,
                    abi.encodeWithSelector(
                        StakingVaultStorageLib.SEL_FORCE_INITIATE_VALIDATOR_REMOVAL, validationID, false, uint32(0)
                    )
                )) {
                uint256 stakeAmount = $.validatorPrincipal[validationID];
                _recordRemovalInFlight($, operatorAddr, validationID, stakeAmount, false);
                contribution += stakeAmount;
                unchecked {
                    ++removals;
                }
                emit IStakingVaultOperations.StakingVault__ValidatorRemovalInitiated(operatorAddr, validationID);
            } else {
                $.validatorPendingRemoval[validationID] = false;
                emit IStakingVaultOperations.StakingVault__ValidatorRemovalFailed(validationID, operatorAddr);
            }
        }
    }

    /// @dev Claim rewards from an operator's validators and split fees.
    function _harvestOperatorValidators(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) internal returns (uint256 totalRewards) {
        address operatorAddr = $.operatorSet.at(operatorIndex);
        IStakingVault.Operator storage op = $.operators[operatorAddr];
        if (!op.active) return 0;

        address mgr = address($.stakingManager);
        uint256 valLen = $.operatorValidators[operatorAddr].length();
        uint256 end = batchSize > type(uint256).max - start ? valLen : start + batchSize;
        if (end > valLen) end = valLen;

        uint256 totalOperatorFee;
        uint256 totalProtocolFee;

        for (uint256 j = start; j < end;) {
            bytes32 validationID = $.operatorValidators[operatorAddr].at(j);
            uint256 reward = _callU256(
                mgr,
                abi.encodeWithSelector(
                    StakingVaultStorageLib.SEL_CLAIM_VALIDATOR_REWARDS, validationID, false, uint32(0)
                )
            );
            if (reward > 0) {
                totalRewards += reward;
                // Both fees taken from TOTAL: protocol gets protocolFeeBips%, operator gets operatorFeeBips%
                uint256 protocolCut = (reward * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
                uint256 operatorCut = (reward * $.operatorFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
                totalOperatorFee += operatorCut;
                totalProtocolFee += protocolCut;
            }
            unchecked {
                ++j;
            }
        }

        if (totalRewards > 0) {
            $.vaultAccountedBalance += totalRewards;
        }

        if (totalOperatorFee > 0) {
            op.accruedFees += totalOperatorFee;
            $.totalAccruedOperatorFees += totalOperatorFee;
        }

        if (totalRewards > 0) {
            // Cap to prevent underflow (must apply BEFORE transfer)
            if (totalOperatorFee + totalProtocolFee > totalRewards) {
                totalProtocolFee = totalRewards - totalOperatorFee;
            }
        }

        if (totalProtocolFee > 0) {
            _sendProtocolFee($, totalProtocolFee);
        }

        if (totalRewards > 0) {
            uint256 poolIncrease = totalRewards - totalOperatorFee - totalProtocolFee;
            emit IStakingVaultOperations.StakingVault__Harvested(totalRewards, totalProtocolFee, poolIncrease);
        }
    }

    /// @dev Claim rewards from an operator's delegations and split fees.
    function _harvestOperatorDelegators(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) internal returns (uint256 totalRewards) {
        address operatorAddr = $.operatorSet.at(operatorIndex);
        IStakingVault.Operator storage op = $.operators[operatorAddr];
        if (!op.active) return 0;

        address mgr = address($.stakingManager);
        uint256 delLen = $.operatorDelegations[operatorAddr].length();
        uint256 end = batchSize > type(uint256).max - start ? delLen : start + batchSize;
        if (end > delLen) end = delLen;

        uint256 totalProtocolFee;
        uint256 totalOperatorFee;

        for (uint256 j = start; j < end;) {
            bytes32 delegationID = $.operatorDelegations[operatorAddr].at(j);
            uint256 netReward = _callU256(
                mgr,
                abi.encodeWithSelector(
                    StakingVaultStorageLib.SEL_CLAIM_DELEGATOR_REWARDS, delegationID, false, uint32(0)
                )
            );

            if (netReward > 0) {
                totalRewards += netReward;
                IStakingVault.DelegatorInfo storage info = $.delegatorInfo[delegationID];

                // Protocol fee on net reward (always)
                uint256 protocolFee = (netReward * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;

                if (info.isVaultOwnedValidator) {
                    // Vault-owned: operator gets fee from net reward
                    uint256 operatorFee = (netReward * $.operatorFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
                    totalOperatorFee += operatorFee;
                    totalProtocolFee += protocolFee;
                } else {
                    // External: recoup protocol's share of external validator's cut
                    // validatorOwnerFee = net × delegationFeeBips / (BIPS - delegationFeeBips)
                    // extraProtocolFee = validatorOwnerFee × protocolFeeBips / BIPS
                    PoSValidatorInfo memory valInfo = _getStakingValidatorInfo(info.validationID);
                    uint256 denominator = StakingVaultStorageLib.BIPS_DENOMINATOR - valInfo.delegationFeeBips;
                    if (denominator > 0) {
                        uint256 validatorOwnerFee = (netReward * valInfo.delegationFeeBips) / denominator;
                        uint256 extraProtocolFee =
                            (validatorOwnerFee * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
                        totalProtocolFee += protocolFee + extraProtocolFee;
                    } else {
                        totalProtocolFee += protocolFee;
                    }
                }
            }
            unchecked {
                ++j;
            }
        }

        if (totalRewards > 0) {
            $.vaultAccountedBalance += totalRewards;
        }

        if (totalOperatorFee > 0) {
            op.accruedFees += totalOperatorFee;
            $.totalAccruedOperatorFees += totalOperatorFee;
        }

        if (totalRewards > 0) {
            // Cap to prevent underflow (must apply BEFORE transfer)
            if (totalOperatorFee + totalProtocolFee > totalRewards) {
                totalProtocolFee = totalRewards - totalOperatorFee;
            }
        }

        if (totalProtocolFee > 0) {
            _sendProtocolFee($, totalProtocolFee);
        }

        if (totalRewards > 0) {
            uint256 poolIncrease = totalRewards - totalOperatorFee - totalProtocolFee;
            emit IStakingVaultOperations.StakingVault__Harvested(totalRewards, totalProtocolFee, poolIncrease);
        }
    }

    /// @dev Roll current-epoch pending amounts into prior-epoch totals when a new epoch starts.
    function _reconcileEpochPending() internal {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 currentEpoch = StakingVaultInternals.getCurrentEpoch();

        if ($.lastPendingReconcileEpoch < currentEpoch) {
            uint256 opLen = $.operatorSet.length();
            for (uint256 i; i < opLen;) {
                address operatorAddr = $.operatorSet.at(i);
                $.operatorPriorEpochPendingAmount[operatorAddr] += $.operatorCurrentEpochPendingAmount[operatorAddr];
                $.operatorCurrentEpochPendingAmount[operatorAddr] = 0;
                unchecked {
                    ++i;
                }
            }
            $.lastPendingReconcileEpoch = currentEpoch;
        }
    }

    /// @dev Revert if the operator's exit debt exceeds the freeze threshold.
    function _checkDebtFreeze(
        address operator
    ) internal view {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        IStakingVault.Operator storage op = $.operators[operator];

        // Combined calculation to avoid divide-before-multiply precision loss
        // threshold = (allocationBips * totalPooledStake * DEBT_FREEZE_THRESHOLD_BIPS) / (BIPS_DENOMINATOR^2)
        uint256 threshold =
            (op.allocationBips
                    * StakingVaultInternals.getTotalPooledStake()
                    * StakingVaultStorageLib.DEBT_FREEZE_THRESHOLD_BIPS)
                / (StakingVaultStorageLib.BIPS_DENOMINATOR * StakingVaultStorageLib.BIPS_DENOMINATOR);

        // Floor: prevent truncation to 0 for small operators
        if (threshold == 0 && op.allocationBips > 0) threshold = 1;

        if ($.operatorExitDebt[operator] > threshold) {
            revert IStakingVault.StakingVault__OperatorDebtTooHigh(operator, $.operatorExitDebt[operator]);
        }
    }

    /// @dev Sum the allocation basis points of all active operators.
    function _getTotalAllocationBips() internal view returns (uint256 totalBips) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 opLen = $.operatorSet.length();
        for (uint256 i; i < opLen;) {
            address operatorAddr = $.operatorSet.at(i);
            IStakingVault.Operator storage op = $.operators[operatorAddr];
            if (op.active) {
                totalBips += op.allocationBips;
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Ensure the vault has sufficient buffer and the operator hasn't exceeded their allocation.
    function _checkBufferAndAllocation(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        uint256 amount
    ) internal view {
        uint256 totalPooled = StakingVaultInternals.getTotalPooledStake();
        uint256 availableStake = StakingVaultInternals.getAvailableStake();
        uint256 minBuffer = (totalPooled * $.liquidityBufferBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        if (availableStake < amount + minBuffer) {
            revert IStakingVault.StakingVault__InsufficientBuffer();
        }

        IStakingVault.Operator storage op = $.operators[msg.sender];
        uint256 maxAllocation = (totalPooled * op.allocationBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        if (op.activeStake + amount > maxAllocation) {
            revert IStakingVault.StakingVault__ExceedsOperatorAllocation(
                msg.sender, amount, maxAllocation > op.activeStake ? maxAllocation - op.activeStake : 0
            );
        }
    }

    /**
     * @notice Record a removal as in-flight for tracking and proportional selection
     * @dev Shared by initiation, force-removal, and adoption paths for both validators and delegators.
     *      Stores currentEpoch+1 to reserve 0 as "unset" sentinel (B4).
     * @param $ Storage pointer
     * @param operatorAddr Operator owning the validator/delegator
     * @param id validationID or delegationID
     * @param amount Stake amount being removed
     * @param isDelegator True for delegator, false for validator
     */
    function _recordRemovalInFlight(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        address operatorAddr,
        bytes32 id,
        uint256 amount,
        bool isDelegator
    ) internal {
        uint256 epochPlusOne = StakingVaultInternals.getCurrentEpoch() + 1;
        if (isDelegator) {
            $.delegatorRemovalInitiatedEpoch[id] = epochPlusOne;
        } else {
            $.validatorRemovalInitiatedEpoch[id] = epochPlusOne;
        }
        $.inFlightExitingAmount += amount;
        $.operatorCurrentEpochPendingAmount[operatorAddr] += amount;
    }

    function _decrementInFlight(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        address operatorAddr,
        uint256 amount,
        uint256 initiatedEpoch
    ) internal {
        // initiatedEpoch == 0 means never tracked (B4: tracked items store epoch+1, always >= 1)
        if (initiatedEpoch == 0) return;

        if ($.inFlightExitingAmount >= amount) {
            $.inFlightExitingAmount -= amount;
        } else {
            $.inFlightExitingAmount = 0;
        }

        if (operatorAddr != address(0)) {
            // Amounts initiated before lastPendingReconcileEpoch have been rolled into prior
            uint256 initEpoch = initiatedEpoch - 1; // safe: initiatedEpoch != 0 (guarded above)
            bool preferPrior = initEpoch <= $.lastPendingReconcileEpoch;

            uint256 remaining = amount;
            if (preferPrior) {
                uint256 prior = $.operatorPriorEpochPendingAmount[operatorAddr];
                if (prior >= remaining) {
                    $.operatorPriorEpochPendingAmount[operatorAddr] = prior - remaining;
                    remaining = 0;
                } else {
                    $.operatorPriorEpochPendingAmount[operatorAddr] = 0;
                    remaining -= prior;
                }
                if (remaining > 0) {
                    uint256 cur = $.operatorCurrentEpochPendingAmount[operatorAddr];
                    $.operatorCurrentEpochPendingAmount[operatorAddr] = cur > remaining ? cur - remaining : 0;
                }
            } else {
                uint256 cur = $.operatorCurrentEpochPendingAmount[operatorAddr];
                if (cur >= remaining) {
                    $.operatorCurrentEpochPendingAmount[operatorAddr] = cur - remaining;
                    remaining = 0;
                } else {
                    $.operatorCurrentEpochPendingAmount[operatorAddr] = 0;
                    remaining -= cur;
                }
                if (remaining > 0) {
                    uint256 prior = $.operatorPriorEpochPendingAmount[operatorAddr];
                    $.operatorPriorEpochPendingAmount[operatorAddr] = prior > remaining ? prior - remaining : 0;
                }
            }
        }

        emit IStakingVaultOperations.StakingVault__InFlightExitingUpdated($.inFlightExitingAmount);
    }

    // ============================================
    // View Helpers (read from main contract storage)
    // ============================================

    function _getStakingValidatorInfo(
        bytes32 validationID
    ) internal view returns (PoSValidatorInfo memory info) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        (bool success, bytes memory data) = address($.stakingManager)
            .staticcall(abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_STAKING_VALIDATOR, validationID));
        if (!success || data.length == 0) {
            return PoSValidatorInfo({
                owner: address(0),
                delegationFeeBips: 0,
                minStakeDuration: 0,
                uptimeSeconds: 0,
                lastRewardClaimTime: 0,
                lastClaimUptimeSeconds: 0
            });
        }
        return abi.decode(data, (PoSValidatorInfo));
    }

    // ============================================
    // Utility Functions
    // ============================================

    /// @dev Low-level call returning a uint256; returns 0 on failure.
    function _callU256(
        address target,
        bytes memory data
    ) internal returns (uint256 result) {
        (bool success, bytes memory ret) = target.call(data);
        if (success && ret.length >= 32) return abi.decode(ret, (uint256));
        return 0;
    }

    /// @dev Low-level call returning success/failure only.
    function _callBool(
        address target,
        bytes memory data
    ) internal returns (bool ok) {
        (ok,) = target.call(data);
    }

    /// @dev Attempt to send protocol fees; escrow if the recipient reverts.
    function _sendProtocolFee(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        uint256 amount
    ) internal {
        $.vaultAccountedBalance -= amount;
        (bool success,) = $.protocolFeeRecipient.call{value: amount}("");
        if (!success) {
            $.vaultAccountedBalance += amount;
            $.pendingProtocolFees += amount;
            emit IStakingVaultOperations.StakingVault__ProtocolFeeEscrowed(amount, $.pendingProtocolFees);
        }
    }

    /// @dev Split rewards from removal completions into operator and protocol fees.
    function _splitRemovalRewards(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        address operatorAddr,
        uint256 rewards
    ) internal {
        uint256 operatorCut = (rewards * $.operatorFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        uint256 protocolCut = (rewards * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        if (operatorAddr != address(0) && operatorCut > 0) {
            $.operators[operatorAddr].accruedFees += operatorCut;
            $.totalAccruedOperatorFees += operatorCut;
        }
        if (protocolCut > 0) {
            _sendProtocolFee($, protocolCut);
        }
    }

    /// @dev Split delegator-removal rewards using the same vault-owned/external policy as harvestDelegators.
    function _splitDelegatorRemovalRewards(
        StakingVaultStorageLib.StakingVaultStorage storage $,
        IStakingVault.DelegatorInfo memory info,
        uint256 rewards
    ) internal {
        uint256 protocolFee = (rewards * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        uint256 operatorFee;

        if (info.isVaultOwnedValidator) {
            operatorFee = (rewards * $.operatorFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
        } else {
            PoSValidatorInfo memory valInfo = _getStakingValidatorInfo(info.validationID);
            uint256 denominator = StakingVaultStorageLib.BIPS_DENOMINATOR - valInfo.delegationFeeBips;
            if (denominator > 0) {
                uint256 validatorOwnerFee = (rewards * valInfo.delegationFeeBips) / denominator;
                uint256 extraProtocolFee =
                    (validatorOwnerFee * $.protocolFeeBips) / StakingVaultStorageLib.BIPS_DENOMINATOR;
                protocolFee += extraProtocolFee;
            }
        }

        if (operatorFee + protocolFee > rewards) {
            protocolFee = rewards - operatorFee;
        }

        if (operatorFee > 0 && info.operator != address(0)) {
            $.operators[info.operator].accruedFees += operatorFee;
            $.totalAccruedOperatorFees += operatorFee;
        }
        if (protocolFee > 0) {
            _sendProtocolFee($, protocolFee);
        }
    }
}

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

import {PChainOwner, ValidatorStatus, IACP99Manager} from "./IACP99Manager.sol";

/**
 * @dev Validator Manager interface that provides additional functionality on top of {IACP99Manager}
 *
 * @custom:security-contact https://github.com/ava-labs/icm-contracts/blob/main/SECURITY.md
 */
interface IValidatorManager is IACP99Manager {
    error InvalidValidatorManagerAddress(address validatorManagerAddress);
    error InvalidWarpOriginSenderAddress(address senderAddress);
    error InvalidValidatorManagerBlockchainID(bytes32 blockchainID);
    error InvalidWarpSourceChainID(bytes32 sourceChainID);
    error InvalidInitializationStatus();
    error InvalidMaximumChurnPercentage(uint8 maximumChurnPercentage);
    error InvalidChurnPeriodLength(uint64 churnPeriodLength);
    error InvalidBLSKeyLength(uint256 length);
    error InvalidNodeID(bytes nodeID);
    error InvalidConversionID(
        bytes32 encodedConversionID,
        bytes32 expectedConversionID
    );
    error InvalidTotalWeight(uint64 weight);
    error InvalidValidationID(bytes32 validationID);
    error InvalidValidatorStatus(ValidatorStatus status);
    error InvalidNonce(uint64 nonce);
    error InvalidWarpMessage();
    error MaxChurnRateExceeded(uint64 churnAmount);
    error NodeAlreadyRegistered(bytes nodeID);
    error UnexpectedRegistrationStatus(bool validRegistration);
    error InvalidPChainOwnerThreshold(
        uint256 threshold,
        uint256 addressesLength
    );
    error InvalidPChainOwnerAddresses();
    error ZeroAddress();

    /**
     * @notice Migrates a validator from the V1 contract to the V2 contract.
     * @param validationID The ID of the validation period to migrate.
     * @param receivedNonce The latest nonce received from the P-Chain.
     */
    function migrateFromV1(bytes32 validationID, uint32 receivedNonce) external;

    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint64 weight
    ) external returns (bytes32);

    /**
     * @notice Resubmits a validator registration message to be sent to the P-Chain.
     * Only necessary if the original message can't be delivered due to validator churn.
     * @param validationID The ID of the validation period being registered.
     */
    function resendRegisterValidatorMessage(bytes32 validationID) external;

    function initiateValidatorRemoval(bytes32 validationID) external;

    /**
     * @notice Resubmits a validator removal message to be sent to the P-Chain.
     * Only necessary if the original message can't be delivered due to validator churn.
     * @param validationID The ID of the validation period being ended.
     */
    function resendValidatorRemovalMessage(bytes32 validationID) external;

    function initiateValidatorWeightUpdate(
        bytes32 validationID,
        uint64 newWeight
    ) external returns (uint64, bytes32);

    /**
     * @notice Returns a validation ID registered to the given nodeID
     * @param nodeID ID of the node associated with the validation ID
     */
    function getNodeValidationID(
        bytes calldata nodeID
    ) external view returns (bytes32);

    function getChurnPeriodSeconds() external view returns (uint64);
}

// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

import {IACP99Manager, PChainOwner} from "./interfaces/IACP99Manager.sol";

/*
 * @title ACP99Manager
 * @notice The ACP99Manager interface represents the functionality for sovereign L1
 * validator management, as specified in ACP-77.
 *
 * @dev ACP99Manager defines the private functions specified in ACP-99.
 * The counterpart to this contract is IACP99Manager, which defines the public functions specified in ACP-99.
 * https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/99-validatorsetmanager-contract
 */
abstract contract ACP99Manager is IACP99Manager {
    // solhint-disable ordering

    /**
     * @notice Initiates validator registration by issuing a RegisterL1ValidatorMessage. The validator should
     * not be considered active until completeValidatorRegistration is called.
     *
     * Emits an {InitiatedValidatorRegistration} event on success.
     *
     * @param nodeID The ID of the node to add to the L1.
     * @param blsPublicKey The BLS public key of the validator.
     * @param remainingBalanceOwner The remaining balance owner of the validator.
     * @param disableOwner The disable owner of the validator.
     * @param weight The weight of the node on the L1.
     * @return validationID The ID of the registered validator.
     */
    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint64 weight
    ) internal virtual returns (bytes32 validationID);

    /**
     * @notice Initiates validator removal by issuing a L1ValidatorWeightMessage with the weight set to zero.
     * The validator should be considered inactive as soon as this function is called.
     *
     * Emits an {InitiatedValidatorRemoval} on success.
     *
     * @param validationID The ID of the validator to remove.
     */
    function _initiateValidatorRemoval(bytes32 validationID) internal virtual;

    /**
     * @notice Initiates a validator weight update by issuing an L1ValidatorWeightMessage with a nonzero weight.
     * The validator weight change should not have any effect until completeValidatorWeightUpdate is successfully called.
     *
     * Emits an {InitiatedValidatorWeightUpdate} event on success.
     *
     * @param validationID The ID of the validator to modify.
     * @param weight The new weight of the validator.
     * @return nonce The validator nonce associated with the weight change.
     * @return messageID The ID of the L1ValidatorWeightMessage used to update the validator's weight.
     */
    function _initiateValidatorWeightUpdate(
        bytes32 validationID,
        uint64 weight
    ) internal virtual returns (uint64 nonce, bytes32 messageID);
}

// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

/// @notice L1 validator status.
enum ValidatorStatus {
    Unknown,
    PendingAdded,
    Active,
    PendingRemoved,
    Completed,
    Invalidated
}

/**
 * @notice Description of the conversion data used to convert
 * a subnet to an L1 on the P-Chain.
 * This data is the pre-image of a hash that is authenticated by the P-Chain
 * and verified by the Validator Manager.
 */
struct ConversionData {
    bytes32 subnetID;
    bytes32 validatorManagerBlockchainID;
    address validatorManagerAddress;
    InitialValidator[] initialValidators;
}

/// @notice Specifies an initial validator, used in the conversion data.
struct InitialValidator {
    bytes nodeID;
    bytes blsPublicKey;
    uint64 weight;
}

/**
 * @notice Specifies the owner of a validator's remaining balance or disable owner on the P-Chain.
 * P-Chain addresses are also 20-bytes, so we use the address type to represent them.
 */
struct PChainOwner {
    uint32 threshold;
    address[] addresses;
}

/**
 * @notice Contains the active state of a Validator.
 * @param status The validator status.
 * @param nodeID The NodeID of the validator.
 * @param startingWeight The weight of the validator at the time of registration.
 * @param sentNonce The current weight update nonce sent by the manager.
 * @param receivedNonce The highest nonce received from the P-Chain.
 * @param weight The current weight of the validator.
 * @param startTime The start time of the validator.
 * @param endTime The end time of the validator.
 */
struct Validator {
    ValidatorStatus status;
    bytes nodeID;
    uint64 startingWeight;
    uint64 sentNonce;
    uint64 receivedNonce;
    uint64 weight;
    uint64 startTime;
    uint64 endTime;
}

/*
 * @title IACP99Manager
 * @notice The IACP99Manager interface represents the functionality for sovereign L1
 * validator management, as specified in ACP-77.
 *
 * @dev IACP99Manager defines the public functions specified in ACP-99.
 * The counterpart to this interface is ACP99Manager, which defines the private functions specified in ACP-99.
 * https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/99-validatorsetmanager-contract
 */
interface IACP99Manager {
    /**
     * @notice Emitted when an initial validator is registered.
     * @notice The field index is the index of the initial validator in the conversion data.
     * This is used along with the subnetID as the ACP-118 justification in
     * signature requests to P-Chain validators over a L1ValidatorRegistrationMessage
     * when removing the validator
     */
    event RegisteredInitialValidator(
        bytes32 indexed validationID,
        bytes20 indexed nodeID,
        bytes32 indexed subnetID,
        uint64 weight
    );
    /// @notice Emitted when a validator registration to the L1 is initiated.
    event InitiatedValidatorRegistration(
        bytes32 indexed validationID,
        bytes20 indexed nodeID,
        bytes32 registrationMessageID,
        uint64 registrationExpiry,
        uint64 weight
    );
    /// @notice Emitted when a validator registration to the L1 is completed.
    event CompletedValidatorRegistration(
        bytes32 indexed validationID,
        uint64 weight
    );
    /// @notice Emitted when removal of an L1 validator is initiated.
    event InitiatedValidatorRemoval(
        bytes32 indexed validationID,
        bytes32 validatorWeightMessageID,
        uint64 weight,
        uint64 endTime
    );
    /// @notice Emitted when removal of an L1 validator is completed.
    event CompletedValidatorRemoval(bytes32 indexed validationID);
    /// @notice Emitted when a validator weight update is initiated.
    event InitiatedValidatorWeightUpdate(
        bytes32 indexed validationID,
        uint64 nonce,
        bytes32 weightUpdateMessageID,
        uint64 weight
    );
    /// @notice Emitted when a validator weight update is completed.
    event CompletedValidatorWeightUpdate(
        bytes32 indexed validationID,
        uint64 nonce,
        uint64 weight
    );

    /**
     * @notice Verifies and sets the initial validator set for the chain by consuming a
     * SubnetToL1ConversionMessage from the P-Chain.
     *
     * Emits a {RegisteredInitialValidator} event for each initial validator in {conversionData}.
     *
     * @param conversionData The Subnet conversion message data used to recompute and verify against the ConversionID.
     * @param messageIndex The index that contains the SubnetToL1ConversionMessage ICM message containing the
     * ConversionID to be verified against the provided {conversionData}.
     */
    function initializeValidatorSet(
        ConversionData calldata conversionData,
        uint32 messageIndex
    ) external;

    /**
     * @notice Completes the validator registration process by returning an acknowledgement of the registration of a
     * validationID from the P-Chain. The validator should not be considered active until this method is successfully called.
     *
     * Emits a {CompletedValidatorRegistration} event on success.
     *
     * @param messageIndex The index of the L1ValidatorRegistrationMessage to be received providing the acknowledgement.
     * @return validationID The ID of the registered validator.
     */
    function completeValidatorRegistration(
        uint32 messageIndex
    ) external returns (bytes32 validationID);

    /**
     * @notice Completes validator removal by consuming a RegisterL1ValidatorMessage from the P-Chain acknowledging
     * that the validator has been removed, or that it was not registered on the P-Chain and the expiry time has passed.
     *
     * Emits a {CompletedValidatorRemoval} on success.
     *
     * @param messageIndex The index of the RegisterL1ValidatorMessage.
     * @return validationID The ID of the validator that was removed.
     */
    function completeValidatorRemoval(
        uint32 messageIndex
    ) external returns (bytes32 validationID);

    /**
     * @notice Completes the validator weight update process by consuming an L1ValidatorWeightMessage from the P-Chain
     * acknowledging the weight update. The validator weight change should not have any effect until this method is successfully called.
     *
     * Emits a {CompletedValidatorWeightUpdate} event on success.
     *
     * @param messageIndex The index of the L1ValidatorWeightMessage message to be received providing the acknowledgement.
     * @return validationID The ID of the validator, retreived from the L1ValidatorWeightMessage.
     * @return nonce The nonce of the validator, retreived from the L1ValidatorWeightMessage.
     */
    function completeValidatorWeightUpdate(
        uint32 messageIndex
    ) external returns (bytes32 validationID, uint64 nonce);

    /// @notice Returns the SubnetID of the L1 tied to this manager
    function subnetID() external view returns (bytes32 id);

    /// @notice Returns the validator details for a given validation ID.
    function getValidator(
        bytes32 validationID
    ) external view returns (Validator memory validator);

    /// @notice Returns the total weight of the current L1 validator set.
    function l1TotalWeight() external view returns (uint64 weight);
}

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

import {IStakingManager} from "./IStakingManager.sol";
import {PChainOwner} from "../ACP99Manager.sol";

/**
 * @notice Interface for Kite native token staking manager
 */
interface IKiteStakingManager is IStakingManager {
    /**
     * @notice Initiates validator registration with native token stake
     * @param nodeID The node ID of the validator
     * @param blsPublicKey The BLS public key of the validator
     * @param remainingBalanceOwner The P-Chain owner to receive remaining balance on removal
     * @param disableOwner The P-Chain owner that can disable the validator
     * @param delegationFeeBips The fee in basis points for delegations
     * @param minStakeDuration The minimum duration for the stake
     * @param rewardRecipient The address to receive rewards
     * @return validationID The ID of the validation period
     */
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        address rewardRecipient
    ) external payable returns (bytes32 validationID);

    /**
     * @notice Initiates delegator registration with native token stake
     * @param validationID The ID of the validator to delegate to
     * @param rewardRecipient The address to receive rewards
     * @return delegationID The ID of the delegation
     */
    function initiateDelegatorRegistration(
        bytes32 validationID,
        address rewardRecipient
    ) external payable returns (bytes32 delegationID);
}

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

/**
 * @notice Interface for Validation and Delegation reward calculators
 */
interface IRewardCalculator {
    /**
     * @notice Calculate incremental reward for a staker during an active staking period.
     * This is used when validators/delegators claim rewards without ending their stake.
     * @param stakeAmount The amount of tokens staked
     * @param lastClaimTime The timestamp of the last reward claim (or staking start if first claim)
     * @param currentTime The current timestamp
     * @param lastClaimUptimeSeconds The uptime seconds at the last claim
     * @param currentUptimeSeconds The current uptime seconds
     * @param validatorStartTime The time the validator started validating
     * @return reward The calculated reward amount
     */
    function calculateIncrementalReward(
        uint256 stakeAmount,
        uint64 lastClaimTime,
        uint64 currentTime,
        uint64 lastClaimUptimeSeconds,
        uint64 currentUptimeSeconds,
        uint64 validatorStartTime
    ) external view returns (uint256 reward);
}

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

import {IValidatorManager} from "../interfaces/IValidatorManager.sol";
import {IRewardCalculator} from "./IRewardCalculator.sol";

/**
 * @dev Delegator status
 */
enum DelegatorStatus {
    Unknown,
    PendingAdded,
    Active,
    PendingRemoved
}

/**
 * @notice Staking Manager settings, used to initialize the Staking Manager
 * @notice baseSettings specified the base settings for the Validator Manager. See {IValidatorManager-ValidatorManagerSettings}
 * @notice minimumStakeAmount is the minimum amount of stake required to stake to a validator
 * @notice maximumStakeAmount is the maximum amount of stake that can be staked to a validator
 * @notice minimumStakeDuration is the minimum duration that validators must stake for
 * @notice minimumDelegationFeeBips is the minimum delegation fee in basis points that validators can charge
 * @notice maximumStakeMultiplier is the multiplier applied to validator's initial stake amount to determine
 * the maximum amount of stake a validator can have with delegations.
 * @notice weightToValueFactor is the factor used to convert validator weight to value
 * @notice rewardCalculator is the reward calculator used to calculate rewards for this validator manager
 * @notice uptimeBlockchainID is the ID of the blockchain that submits uptime proofs.
 * This must be a blockchain validated by the subnetID that this contract manages.
 */
struct StakingManagerSettings {
    IValidatorManager manager;
    uint256 minimumStakeAmount;
    uint256 maximumStakeAmount;
    uint64 minimumStakeDuration;
    uint16 minimumDelegationFeeBips;
    uint8 maximumStakeMultiplier;
    uint256 weightToValueFactor;
    IRewardCalculator rewardCalculator;
    bytes32 uptimeBlockchainID;
}

/**
 * @dev Contains the active state of a Delegator
 */
struct Delegator {
    DelegatorStatus status;
    address owner;
    bytes32 validationID;
    uint64 weight;
    uint64 startTime;
    uint64 startingNonce;
    uint64 endingNonce;
    uint64 lastRewardClaimTime;
    uint64 lastClaimUptimeSeconds;
}

/**
 * @dev Describes the active state of a PoS Validator in addition the information in {IValidatorManager-Validator}
 */
struct PoSValidatorInfo {
    address owner;
    uint16 delegationFeeBips;
    uint64 minStakeDuration;
    uint64 uptimeSeconds;
    uint64 lastRewardClaimTime;
    uint64 lastClaimUptimeSeconds;
}

/**
 * @notice Interface for Proof of Stake Validator Managers
 */
interface IStakingManager {
    /**
     * @notice Event emitted when a delegator registration is initiated
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period being delegated to
     * @param delegatorAddress The address of the delegator
     * @param nonce The message nonce used to update the validator weight
     * @param validatorWeight The updated validator weight that is sent to the P-Chain
     * @param delegatorWeight The weight of the delegator
     * @param setWeightMessageID The ID of the ICM message that updates the validator's weight on the P-Chain
     * @param rewardRecipient The address of the recipient of the delegator's rewards
     * @param stakeAmount The amount of tokens staked by the delegator
     */
    event InitiatedDelegatorRegistration(
        bytes32 indexed delegationID,
        bytes32 indexed validationID,
        address indexed delegatorAddress,
        uint64 nonce,
        uint64 validatorWeight,
        uint64 delegatorWeight,
        bytes32 setWeightMessageID,
        address rewardRecipient,
        uint256 stakeAmount
    );

    /**
     * @notice Event emitted when a staking validator registration is initiated
     * @param validationID The ID of the validation period
     * @param owner The address of the owner of the validator
     * @param delegationFeeBips The delegation fee in basis points
     * @param minStakeDuration The minimum stake duration
     * @param rewardRecipient The address of the recipient of the validator's rewards
     * @param stakeAmount The amount of tokens staked by the validator
     */
    event InitiatedStakingValidatorRegistration(
        bytes32 indexed validationID,
        address indexed owner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        address rewardRecipient,
        uint256 stakeAmount
    );

    /**
     * @notice Event emitted when a delegator registration is completed
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period
     * @param startTime The time at which the registration was completed
     */
    event CompletedDelegatorRegistration(
        bytes32 indexed delegationID,
        bytes32 indexed validationID,
        uint256 startTime
    );

    /**
     * @notice Event emitted when delegator removal is initiated
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation period the delegator was staked to
     */
    event InitiatedDelegatorRemoval(
        bytes32 indexed delegationID,
        bytes32 indexed validationID
    );

    /**
     * @notice Event emitted when delegator removal is completed
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validator the delegator was staked to
     * @param stakeAmount The amount of tokens unlocked (principal)
     * @param rewards The rewards given to the delegator
     * @param fees The portion of the delegator's rewards paid to the validator
     */
    event CompletedDelegatorRemoval(
        bytes32 indexed delegationID,
        bytes32 indexed validationID,
        uint256 stakeAmount,
        uint256 rewards,
        uint256 fees
    );

    /**
     * @notice Event emitted when a staking validator removal is completed
     * @param validationID The ID of the validation period
     * @param stakeAmount The amount of tokens unlocked (principal)
     * @param rewards The total rewards distributed to the validator
     */
    event CompletedStakingValidatorRemoval(
        bytes32 indexed validationID,
        uint256 stakeAmount,
        uint256 rewards
    );

    /**
     * @notice Event emitted when the uptime of a validator is updated. Only emitted when the uptime is greater than the stored uptime.
     * @param validationID The ID of the validation period
     * @param uptime The updated uptime of the validator
     */
    event UptimeUpdated(bytes32 indexed validationID, uint64 uptime);

    /**
     * @notice Event emitted when a validator claims rewards. Emitted when validation rewards and delegation fees are claimed.
     * @param validationID The ID of the validation period
     * @param recipient The address of the recipient of the rewards
     * @param amount The amount of rewards claimed
     */
    event ValidatorRewardClaimed(
        bytes32 indexed validationID,
        address indexed recipient,
        uint256 amount
    );

    /**
     * @notice Event emitted when delegation fees (commission) are accrued to a validator.
     * @param validationID The ID of the validation period
     * @param delegationID The ID of the delegation that generated the fees
     * @param amount The amount of delegation fees accrued
     */
    event DelegationFeesAccrued(
        bytes32 indexed validationID,
        bytes32 indexed delegationID,
        uint256 amount
    );

    /**
     * @notice Event emitted when a validator withdraws accumulated delegation fees (commission).
     * @param validationID The ID of the validation period
     * @param recipient The address of the recipient of the fees
     * @param amount The amount of delegation fees withdrawn
     */
    event DelegationFeesWithdrawn(
        bytes32 indexed validationID,
        address indexed recipient,
        uint256 amount
    );

    /**
     * @notice Event emitted when the recipient of a validator's rewards is changed.
     * @param validationID The ID of the validation period
     * @param recipient The address of the new recipient of the rewards
     * @param oldRecipient The address of the old recipient of the rewards
     */
    event ValidatorRewardRecipientChanged(
        bytes32 indexed validationID,
        address indexed recipient,
        address indexed oldRecipient
    );

    /**
     * @notice Event emitted when a delegator claims rewards.
     * @param delegationID The ID of the delegation
     * @param recipient The address of the recipient of the rewards
     * @param amount The amount of rewards claimed
     */
    event DelegatorRewardClaimed(
        bytes32 indexed delegationID,
        address indexed recipient,
        uint256 amount
    );

    /**
     * @notice Event emitted when the recipient of a delegator's rewards is changed.
     * @param delegationID The ID of the validation period
     * @param recipient The address of the new recipient of the rewards
     * @param oldRecipient The address of the old recipient of the rewards
     */
    event DelegatorRewardRecipientChanged(
        bytes32 indexed delegationID,
        address indexed recipient,
        address indexed oldRecipient
    );

    /**
     * @notice Updates the uptime of the validationID if the submitted proof is greated than the stored uptime.
     * Anybody may call this function to ensure the stored uptime is accurate. Callable only when the validation period is active.
     * @param validationID The ID of the validation period
     * @param messageIndex The index of the ICM message to be received providing the uptime proof
     */
    function submitUptimeProof(
        bytes32 validationID,
        uint32 messageIndex
    ) external;

    /**
     * @notice Completes validator registration by dispatching to the IValidatorManager to update the validator status,
     * and locking stake.
     *
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement from the P-Chain.
     * This is forwarded to the IValidatorManager to be parsed.
     * @return The ID of the validator that was registered.
     */
    function completeValidatorRegistration(
        uint32 messageIndex
    ) external returns (bytes32);

    /**
     * @notice Begins the process of ending an active validation period, and reverts if the validation period is not eligible
     * for uptime-based rewards. This function is used to exit the validator set when rewards are expected.
     * The validation period must have been previously started by a successful call to {completeValidatorRegistration} with the given validationID.
     * Any rewards for this validation period will stop accruing when this function is called.
     * Note: Reverts if the uptime is not eligible for rewards.
     * @param validationID The ID of the validation period being ended.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period. If no uptime proof is provided,
     * the latest known uptime will be used.
     * @param messageIndex The index of the ICM message to be received providing the uptime proof.
     */
    function initiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Begins the process of ending an active validation period, but does not revert if the latest known uptime
     * is not sufficient to collect uptime-based rewards. This function is used to exit the validator set when rewards are
     * not expected.
     * The validation period must have been previously started by a successful call to {completeValidatorRegistration} with the given validationID.
     * Any rewards for this validation period will stop accruing when this function is called.
     * @param validationID The ID of the validation period being ended.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period. If no uptime proof is provided,
     * the latest known uptime will be used.
     * @param messageIndex The index of the ICM message to be received providing the uptime proof.
     */
    function forceInitiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Completes validator removal by dispatching to the IValidatorManager to update the validator status,
     * and unlocking stake.
     *
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement from the P-Chain.
     * This is forwarded to the IValidatorManager to be parsed.
     * @return The ID of the validator that was removed.
     */
    function completeValidatorRemoval(
        uint32 messageIndex
    ) external returns (bytes32);

    /**
     * @notice Completes the delegator registration process by submitting an acknowledgement of the registration of a
     * validationID from the P-Chain.
     * Any P-Chain acknowledgement with a nonce greater than or equal to the nonce used to initiate registration of the
     * delegator is valid, as long as that nonce has been sent by the contract. For the purposes of computing delegation rewards,
     * the delegation is considered active after this function is completed.
     * Note: Only the specified delegation will be marked as registered, even if the validator weight update
     * message implicitly includes multiple weight changes.
     * @param delegationID The ID of the delegation being registered.
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement.
     * @param uptimeMessageIndex The index of the ICM message providing the uptime proof. Required to ensure
     * accurate reward calculation from the registration time.
     */
    function completeDelegatorRegistration(
        bytes32 delegationID,
        uint32 messageIndex,
        uint32 uptimeMessageIndex
    ) external;

    /**
     * @notice Begins the process of removing a delegator from a validation period, and reverts if the delegation is not eligible for rewards.
     * The delegator must have been previously registered with the given validationID. For the purposes of computing delegation rewards,
     * the delegation period is considered ended when this function is called. Uses the supplied uptime proof to calculate rewards.
     * If none is provided in the call, the latest known uptime will be used. Reverts if the uptime is not eligible for rewards.
     * Note: This function can only be called by the address that registered the delegation.
     * Note: Reverts if the uptime is not eligible for rewards.
     * @param delegationID The ID of the delegation being removed.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period.
     * If the validator has completed its validation period, it has already provided an uptime proof, so {includeUptimeProof}
     * will be ignored and can be set to false. If the validator has not completed its validation period and no uptime proof
     * is provided, the latest known uptime will be used.
     * @param messageIndex If {includeUptimeProof} is true, the index of the ICM message to be received providing the
     * uptime proof.
     */
    function initiateDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Begins the process of removing a delegator from a validation period, but does not revert if the delegation is not eligible for rewards.
     * The delegator must have been previously registered with the given validationID. For the purposes of computing delegation rewards,
     * the delegation period is considered ended when this function is called. Uses the supplied uptime proof to calculate rewards.
     * If none is provided in the call, the latest known uptime will be used. Reverts if the uptime is not eligible for rewards.
     * Note: This function can only be called by the address that registered the delegation.
     * @param delegationID The ID of the delegation being removed.
     * @param includeUptimeProof Whether or not an uptime proof is provided for the validation period.
     * If the validator has completed its validation period, it has already provided an uptime proof, so {includeUptimeProof}
     * will be ignored and can be set to false. If the validator has not completed its validation period and no uptime proof
     * is provided, the latest known uptime will be used.
     * @param messageIndex If {includeUptimeProof} is true, the index of the ICM message to be received providing the
     * uptime proof.
     */
    function forceInitiateDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external;

    /**
     * @notice Resubmits a delegator registration or delegator end message to be sent to the P-Chain.
     * Only necessary if the original message can't be delivered due to validator churn.
     * @param delegationID The ID of the delegation.
     */
    function resendUpdateDelegator(bytes32 delegationID) external;

    /**
     * @notice Completes the process of ending a delegation by receiving an acknowledgement from the P-Chain.
     * Any P-Chain acknowledgement with a nonce greater than or equal to the nonce used to initiate the end of the
     * delegator's delegation is valid, as long as that nonce has been sent by the contract. This is because the validator
     * weight change pertaining to the delegation ending is included in any subsequent validator weight update messages.
     * Note: Only the specified delegation will be marked as completed, even if the validator weight update
     * message implicitly includes multiple weight changes.
     * @param delegationID The ID of the delegation being removed.
     * @param messageIndex The index of the ICM message to be received providing the acknowledgement.
     */
    function completeDelegatorRemoval(
        bytes32 delegationID,
        uint32 messageIndex
    ) external;

    /**
     * @notice Changes the address of the recipient of the validator's rewards for a validation period.
     * @param validationID The ID of the validation period being ended.
     * @param recipient The address to receive the rewards.
     */
    function changeValidatorRewardRecipient(
        bytes32 validationID,
        address recipient
    ) external;

    /**
     * @notice Changes the address of the recipient of the delegator's rewards for a delegation period.
     * @param delegationID The ID of the validation period being ended.
     * @param recipient The address to receive the rewards.
     */
    function changeDelegatorRewardRecipient(
        bytes32 delegationID,
        address recipient
    ) external;

    /**
     * @notice Claims accumulated rewards for a validator.
     * - For Active validators: calculates and claims incremental rewards
     * - For Completed validators: claims any pending rewards (delegation fees or rewards that failed to distribute)
     * @param validationID The ID of the validation period.
     * @param includeUptimeProof Whether to include an uptime proof to update the uptime. If false, the latest stored uptime is used (only for Active validators).
     * @param messageIndex The index of the ICM message providing the uptime proof (ignored if includeUptimeProof is false).
     * @return reward The amount of rewards claimed.
     */
    function claimValidatorRewards(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external returns (uint256 reward);

    /**
     * @notice Claims accumulated rewards for a delegator.
     * - For Active delegators: calculates and claims incremental rewards
     * - For completed delegators (Unknown status): claims any pending rewards that failed to distribute during removal
     * @param delegationID The ID of the delegation.
     * @param includeUptimeProof Whether to include an uptime proof to update the uptime. If false, the latest stored uptime is used.
     * @param messageIndex The index of the ICM message providing the uptime proof (ignored if includeUptimeProof is false).
     * @return reward The amount of rewards claimed (after commission deduction).
     */
    function claimDelegatorRewards(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external returns (uint256 reward);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (access/IAccessControl.sol)

pragma solidity >=0.8.4;

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/Arrays.sol)
// This file was procedurally generated from scripts/generate/templates/Arrays.js.

pragma solidity ^0.8.24;

import {Comparators} from "./Comparators.sol";
import {SlotDerivation} from "./SlotDerivation.sol";
import {StorageSlot} from "./StorageSlot.sol";
import {Math} from "./math/Math.sol";

/**
 * @dev Collection of functions related to array types.
 */
library Arrays {
    using SlotDerivation for bytes32;
    using StorageSlot for bytes32;

    /**
     * @dev Sort an array of uint256 (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        uint256[] memory array,
        function(uint256, uint256) pure returns (bool) comp
    ) internal pure returns (uint256[] memory) {
        _quickSort(_begin(array), _end(array), comp);
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of uint256 in increasing order.
     */
    function sort(uint256[] memory array) internal pure returns (uint256[] memory) {
        sort(array, Comparators.lt);
        return array;
    }

    /**
     * @dev Sort an array of address (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        address[] memory array,
        function(address, address) pure returns (bool) comp
    ) internal pure returns (address[] memory) {
        sort(_castToUint256Array(array), _castToUint256Comp(comp));
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of address in increasing order.
     */
    function sort(address[] memory array) internal pure returns (address[] memory) {
        sort(_castToUint256Array(array), Comparators.lt);
        return array;
    }

    /**
     * @dev Sort an array of bytes32 (in memory) following the provided comparator function.
     *
     * This function does the sorting "in place", meaning that it overrides the input. The object is returned for
     * convenience, but that returned value can be discarded safely if the caller has a memory pointer to the array.
     *
     * NOTE: this function's cost is `O(n · log(n))` in average and `O(n²)` in the worst case, with n the length of the
     * array. Using it in view functions that are executed through `eth_call` is safe, but one should be very careful
     * when executing this as part of a transaction. If the array being sorted is too large, the sort operation may
     * consume more gas than is available in a block, leading to potential DoS.
     *
     * IMPORTANT: Consider memory side-effects when using custom comparator functions that access memory in an unsafe way.
     */
    function sort(
        bytes32[] memory array,
        function(bytes32, bytes32) pure returns (bool) comp
    ) internal pure returns (bytes32[] memory) {
        sort(_castToUint256Array(array), _castToUint256Comp(comp));
        return array;
    }

    /**
     * @dev Variant of {sort} that sorts an array of bytes32 in increasing order.
     */
    function sort(bytes32[] memory array) internal pure returns (bytes32[] memory) {
        sort(_castToUint256Array(array), Comparators.lt);
        return array;
    }

    /**
     * @dev Performs a quick sort of a segment of memory. The segment sorted starts at `begin` (inclusive), and stops
     * at end (exclusive). Sorting follows the `comp` comparator.
     *
     * Invariant: `begin <= end`. This is the case when initially called by {sort} and is preserved in subcalls.
     *
     * IMPORTANT: Memory locations between `begin` and `end` are not validated/zeroed. This function should
     * be used only if the limits are within a memory array.
     */
    function _quickSort(uint256 begin, uint256 end, function(uint256, uint256) pure returns (bool) comp) private pure {
        unchecked {
            if (end - begin < 0x40) return;

            // Use first element as pivot
            uint256 pivot = _mload(begin);
            // Position where the pivot should be at the end of the loop
            uint256 pos = begin;

            for (uint256 it = begin + 0x20; it < end; it += 0x20) {
                if (comp(_mload(it), pivot)) {
                    // If the value stored at the iterator's position comes before the pivot, we increment the
                    // position of the pivot and move the value there.
                    pos += 0x20;
                    _swap(pos, it);
                }
            }

            _swap(begin, pos); // Swap pivot into place
            _quickSort(begin, pos, comp); // Sort the left side of the pivot
            _quickSort(pos + 0x20, end, comp); // Sort the right side of the pivot
        }
    }

    /**
     * @dev Pointer to the memory location of the first element of `array`.
     */
    function _begin(uint256[] memory array) private pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := add(array, 0x20)
        }
    }

    /**
     * @dev Pointer to the memory location of the first memory word (32bytes) after `array`. This is the memory word
     * that comes just after the last element of the array.
     */
    function _end(uint256[] memory array) private pure returns (uint256 ptr) {
        unchecked {
            return _begin(array) + array.length * 0x20;
        }
    }

    /**
     * @dev Load memory word (as a uint256) at location `ptr`.
     */
    function _mload(uint256 ptr) private pure returns (uint256 value) {
        assembly {
            value := mload(ptr)
        }
    }

    /**
     * @dev Swaps the elements memory location `ptr1` and `ptr2`.
     */
    function _swap(uint256 ptr1, uint256 ptr2) private pure {
        assembly {
            let value1 := mload(ptr1)
            let value2 := mload(ptr2)
            mstore(ptr1, value2)
            mstore(ptr2, value1)
        }
    }

    /// @dev Helper: low level cast address memory array to uint256 memory array
    function _castToUint256Array(address[] memory input) private pure returns (uint256[] memory output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast bytes32 memory array to uint256 memory array
    function _castToUint256Array(bytes32[] memory input) private pure returns (uint256[] memory output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast address comp function to uint256 comp function
    function _castToUint256Comp(
        function(address, address) pure returns (bool) input
    ) private pure returns (function(uint256, uint256) pure returns (bool) output) {
        assembly {
            output := input
        }
    }

    /// @dev Helper: low level cast bytes32 comp function to uint256 comp function
    function _castToUint256Comp(
        function(bytes32, bytes32) pure returns (bool) input
    ) private pure returns (function(uint256, uint256) pure returns (bool) output) {
        assembly {
            output := input
        }
    }

    /**
     * @dev Searches a sorted `array` and returns the first index that contains
     * a value greater or equal to `element`. If no such index exists (i.e. all
     * values in the array are strictly less than `element`), the array length is
     * returned. Time complexity O(log n).
     *
     * NOTE: The `array` is expected to be sorted in ascending order, and to
     * contain no repeated elements.
     *
     * IMPORTANT: Deprecated. This implementation behaves as {lowerBound} but lacks
     * support for repeated elements in the array. The {lowerBound} function should
     * be used instead.
     */
    function findUpperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value > element) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        // At this point `low` is the exclusive upper bound. We will return the inclusive upper bound.
        if (low > 0 && unsafeAccess(array, low - 1).value == element) {
            return low - 1;
        } else {
            return low;
        }
    }

    /**
     * @dev Searches an `array` sorted in ascending order and returns the first
     * index that contains a value greater or equal than `element`. If no such index
     * exists (i.e. all values in the array are strictly less than `element`), the array
     * length is returned. Time complexity O(log n).
     *
     * See C++'s https://en.cppreference.com/w/cpp/algorithm/lower_bound[lower_bound].
     */
    function lowerBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value < element) {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            } else {
                high = mid;
            }
        }

        return low;
    }

    /**
     * @dev Searches an `array` sorted in ascending order and returns the first
     * index that contains a value strictly greater than `element`. If no such index
     * exists (i.e. all values in the array are strictly less than `element`), the array
     * length is returned. Time complexity O(log n).
     *
     * See C++'s https://en.cppreference.com/w/cpp/algorithm/upper_bound[upper_bound].
     */
    function upperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeAccess(array, mid).value > element) {
                high = mid;
            } else {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            }
        }

        return low;
    }

    /**
     * @dev Same as {lowerBound}, but with an array in memory.
     */
    function lowerBoundMemory(uint256[] memory array, uint256 element) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeMemoryAccess(array, mid) < element) {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            } else {
                high = mid;
            }
        }

        return low;
    }

    /**
     * @dev Same as {upperBound}, but with an array in memory.
     */
    function upperBoundMemory(uint256[] memory array, uint256 element) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 high = array.length;

        if (high == 0) {
            return 0;
        }

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds towards zero (it does integer division with truncation).
            if (unsafeMemoryAccess(array, mid) > element) {
                high = mid;
            } else {
                // this cannot overflow because mid < high
                unchecked {
                    low = mid + 1;
                }
            }
        }

        return low;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new address array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(address[] memory array, uint256 start) internal pure returns (address[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new address array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(address[] memory array, uint256 start, uint256 end) internal pure returns (address[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        address[] memory result = new address[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new bytes32 array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(bytes32[] memory array, uint256 start) internal pure returns (bytes32[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new bytes32 array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(bytes32[] memory array, uint256 start, uint256 end) internal pure returns (bytes32[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        bytes32[] memory result = new bytes32[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to the end of `array` into a new uint256 array in
     * memory.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(uint256[] memory array, uint256 start) internal pure returns (uint256[] memory) {
        return slice(array, start, array.length);
    }

    /**
     * @dev Copies the content of `array`, from `start` (included) to `end` (excluded) into a new uint256 array in
     * memory. The `end` argument is truncated to the length of the `array`.
     *
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/slice[Javascript's `Array.slice`]
     */
    function slice(uint256[] memory array, uint256 start, uint256 end) internal pure returns (uint256[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // allocate and copy
        uint256[] memory result = new uint256[](end - start);
        assembly ("memory-safe") {
            mcopy(add(result, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
        }

        return result;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(address[] memory array, uint256 start) internal pure returns (address[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(address[] memory array, uint256 start, uint256 end) internal pure returns (address[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        address[] memory array,
        uint256 pos,
        address[] memory replacement
    ) internal pure returns (address[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        address[] memory array,
        uint256 pos,
        address[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (address[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // allocate and copy
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(bytes32[] memory array, uint256 start) internal pure returns (bytes32[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(bytes32[] memory array, uint256 start, uint256 end) internal pure returns (bytes32[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        bytes32[] memory array,
        uint256 pos,
        bytes32[] memory replacement
    ) internal pure returns (bytes32[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        bytes32[] memory array,
        uint256 pos,
        bytes32[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (bytes32[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // allocate and copy
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to the end of `array` to the start of that array.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(uint256[] memory array, uint256 start) internal pure returns (uint256[] memory) {
        return splice(array, start, array.length);
    }

    /**
     * @dev Moves the content of `array`, from `start` (included) to `end` (excluded) to the start of that array. The
     * `end` argument is truncated to the length of the `array`.
     *
     * NOTE: This function modifies the provided array in place. If you need to preserve the original array, use {slice} instead.
     * NOTE: replicates the behavior of https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice[Javascript's `Array.splice`]
     */
    function splice(uint256[] memory array, uint256 start, uint256 end) internal pure returns (uint256[] memory) {
        // sanitize
        end = Math.min(end, array.length);
        start = Math.min(start, end);

        // move and resize
        assembly ("memory-safe") {
            mcopy(add(array, 0x20), add(add(array, 0x20), mul(start, 0x20)), mul(sub(end, start), 0x20))
            mstore(array, sub(end, start))
        }

        return array;
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with all elements from `replacement`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`).
     * If `pos >= array.length`, no replacement occurs and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        uint256[] memory array,
        uint256 pos,
        uint256[] memory replacement
    ) internal pure returns (uint256[] memory) {
        return replace(array, pos, replacement, 0, replacement.length);
    }

    /**
     * @dev Replaces elements in `array` starting at `pos` with elements from `replacement` starting at `offset`.
     * Copies at most `length` elements from `replacement` to `array`.
     *
     * Parameters are clamped to valid ranges (i.e. `pos` is clamped to `[0, array.length]`, `offset` is
     * clamped to `[0, replacement.length]`, and `length` is clamped to `min(length, replacement.length - offset,
     * array.length - pos)`). If `pos >= array.length` or `offset >= replacement.length`, no replacement occurs
     * and the array is returned unchanged.
     *
     * NOTE: This function modifies the provided array in place.
     */
    function replace(
        uint256[] memory array,
        uint256 pos,
        uint256[] memory replacement,
        uint256 offset,
        uint256 length
    ) internal pure returns (uint256[] memory) {
        // sanitize
        pos = Math.min(pos, array.length);
        offset = Math.min(offset, replacement.length);
        length = Math.min(length, Math.min(replacement.length - offset, array.length - pos));

        // allocate and copy
        assembly ("memory-safe") {
            mcopy(
                add(add(array, 0x20), mul(pos, 0x20)),
                add(add(replacement, 0x20), mul(offset, 0x20)),
                mul(length, 0x20)
            )
        }

        return array;
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(address[] storage arr, uint256 pos) internal pure returns (StorageSlot.AddressSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getAddressSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(bytes32[] storage arr, uint256 pos) internal pure returns (StorageSlot.Bytes32Slot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getBytes32Slot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(uint256[] storage arr, uint256 pos) internal pure returns (StorageSlot.Uint256Slot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getUint256Slot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(bytes[] storage arr, uint256 pos) internal pure returns (StorageSlot.BytesSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getBytesSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeAccess(string[] storage arr, uint256 pos) internal pure returns (StorageSlot.StringSlot storage) {
        bytes32 slot;
        assembly ("memory-safe") {
            slot := arr.slot
        }
        return slot.deriveArray().offset(pos).getStringSlot();
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(address[] memory arr, uint256 pos) internal pure returns (address res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(bytes32[] memory arr, uint256 pos) internal pure returns (bytes32 res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(uint256[] memory arr, uint256 pos) internal pure returns (uint256 res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(bytes[] memory arr, uint256 pos) internal pure returns (bytes memory res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Access an array in an "unsafe" way. Skips solidity "index-out-of-range" check.
     *
     * WARNING: Only use if you are certain `pos` is lower than the array length.
     */
    function unsafeMemoryAccess(string[] memory arr, uint256 pos) internal pure returns (string memory res) {
        assembly {
            res := mload(add(add(arr, 0x20), mul(pos, 0x20)))
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(address[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(bytes32[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(uint256[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(bytes[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }

    /**
     * @dev Helper to set the length of a dynamic array. Directly writing to `.length` is forbidden.
     *
     * WARNING: this does not clear elements if length is reduced, or initialize elements if length is increased.
     */
    function unsafeSetLength(string[] storage array, uint256 len) internal {
        assembly ("memory-safe") {
            sstore(array.slot, len)
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Comparators.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides a set of functions to compare values.
 *
 * _Available since v5.1._
 */
library Comparators {
    function lt(uint256 a, uint256 b) internal pure returns (bool) {
        return a < b;
    }

    function gt(uint256 a, uint256 b) internal pure returns (bool) {
        return a > b;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

pragma solidity ^0.8.20;

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/SlotDerivation.sol)
// This file was procedurally generated from scripts/generate/templates/SlotDerivation.js.

pragma solidity ^0.8.20;

/**
 * @dev Library for computing storage (and transient storage) locations from namespaces and deriving slots
 * corresponding to standard patterns. The derivation method for array and mapping matches the storage layout used by
 * the solidity language / compiler.
 *
 * See https://docs.soliditylang.org/en/v0.8.20/internals/layout_in_storage.html#mappings-and-dynamic-arrays[Solidity docs for mappings and dynamic arrays.].
 *
 * Example usage:
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using StorageSlot for bytes32;
 *     using SlotDerivation for *;
 *
 *     // Declare a namespace
 *     string private constant _NAMESPACE = "<namespace>"; // eg. OpenZeppelin.Slot
 *
 *     function setValueInNamespace(uint256 key, address newValue) internal {
 *         _NAMESPACE.erc7201Slot().deriveMapping(key).getAddressSlot().value = newValue;
 *     }
 *
 *     function getValueInNamespace(uint256 key) internal view returns (address) {
 *         return _NAMESPACE.erc7201Slot().deriveMapping(key).getAddressSlot().value;
 *     }
 * }
 * ```
 *
 * TIP: Consider using this library along with {StorageSlot}.
 *
 * NOTE: This library provides a way to manipulate storage locations in a non-standard way. Tooling for checking
 * upgrade safety will ignore the slots accessed through this library.
 *
 * _Available since v5.1._
 */
library SlotDerivation {
    /**
     * @dev Derive an ERC-7201 slot from a string (namespace).
     */
    function erc7201Slot(string memory namespace) internal pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, sub(keccak256(add(namespace, 0x20), mload(namespace)), 1))
            slot := and(keccak256(0x00, 0x20), not(0xff))
        }
    }

    /**
     * @dev Add an offset to a slot to get the n-th element of a structure or an array.
     */
    function offset(bytes32 slot, uint256 pos) internal pure returns (bytes32 result) {
        unchecked {
            return bytes32(uint256(slot) + pos);
        }
    }

    /**
     * @dev Derive the location of the first element in an array from the slot where the length is stored.
     */
    function deriveArray(bytes32 slot) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, slot)
            result := keccak256(0x00, 0x20)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, address key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, and(key, shr(96, not(0))))
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bool key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, iszero(iszero(key)))
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bytes32 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, uint256 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, int256 key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, key)
            mstore(0x20, slot)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, string memory key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let length := mload(key)
            let begin := add(key, 0x20)
            let end := add(begin, length)
            let cache := mload(end)
            mstore(end, slot)
            result := keccak256(begin, add(length, 0x20))
            mstore(end, cache)
        }
    }

    /**
     * @dev Derive the location of a mapping element from the key.
     */
    function deriveMapping(bytes32 slot, bytes memory key) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let length := mload(key)
            let begin := add(key, 0x20)
            let end := add(begin, length)
            let cache := mload(end)
            mstore(end, slot)
            result := keccak256(begin, add(length, 0x20))
            mstore(end, cache)
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

pragma solidity ^0.8.20;

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC-1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     // Define the slot. Alternatively, use the SlotDerivation library to derive the slot.
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * TIP: Consider using this library along with {SlotDerivation}.
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct Int256Slot {
        int256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `Int256Slot` with member `value` located at `slot`.
     */
    function getInt256Slot(bytes32 slot) internal pure returns (Int256Slot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns a `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns a `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        assembly ("memory-safe") {
            r.slot := store.slot
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;

import {Panic} from "../Panic.sol";
import {SafeCast} from "./SafeCast.sol";

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `condition ? a : b`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `condition ? a : b`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // (a + b) / 2 can overflow.
            return (a & b) + (a ^ b) / 2;
        }
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory buffer) private pure returns (bool) {
        uint256 chunk;
        for (uint256 i = 0; i < buffer.length; i += 0x20) {
            // See _unsafeReadBytesOffset from utils/Bytes.sol
            assembly ("memory-safe") {
                chunk := mload(add(add(buffer, 0x20), i))
            }
            if (chunk >> (8 * saturatingSub(i + 0x20, buffer.length)) != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the first 16 bytes (most significant half).
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }

    /**
     * @dev Counts the number of leading zero bits in a uint256.
     */
    function clz(uint256 x) internal pure returns (uint256) {
        return ternary(x == 0, 256, 255 - log2(x));
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

pragma solidity ^0.8.20;

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in a uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in a uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev A uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.5.0) (utils/structs/EnumerableSet.sol)
// This file was procedurally generated from scripts/generate/templates/EnumerableSet.js.

pragma solidity ^0.8.24;

import {Arrays} from "../Arrays.sol";
import {Math} from "../math/Math.sol";

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 * - Set can be cleared (all elements removed) in O(n).
 *
 * ```solidity
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * The following types are supported:
 *
 * - `bytes32` (`Bytes32Set`) since v3.3.0
 * - `address` (`AddressSet`) since v3.3.0
 * - `uint256` (`UintSet`) since v3.3.0
 * - `string` (`StringSet`) since v5.4.0
 * - `bytes` (`BytesSet`) since v5.4.0
 * - `bytes4` (`Bytes4Set`) since v5.6.0
 *
 * [WARNING]
 * ====
 * Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * unusable.
 * See https://github.com/ethereum/solidity/pull/11843[ethereum/solidity#11843] for more info.
 *
 * In order to clean an EnumerableSet, you can either remove all elements one by one or create a fresh instance using an
 * array of EnumerableSet.
 * ====
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(bytes32 value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                bytes32 lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: This function has an unbounded cost that scales with set size. Developers should keep in mind that
     * using it may render the function uncallable if the set grows to the point where clearing it consumes too much
     * gas to fit in a block.
     */
    function _clear(Set storage set) private {
        uint256 len = _length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set) private view returns (bytes32[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function _values(Set storage set, uint256 start, uint256 end) private view returns (bytes32[] memory) {
        unchecked {
            end = Math.min(end, _length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            bytes32[] memory result = new bytes32[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(Bytes32Set storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set) internal view returns (bytes32[] memory) {
        bytes32[] memory store = _values(set._inner);
        bytes32[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes32Set storage set, uint256 start, uint256 end) internal view returns (bytes32[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        bytes32[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // Bytes4Set

    struct Bytes4Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes4Set storage set, bytes4 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes4Set storage set, bytes4 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(Bytes4Set storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes4Set storage set, bytes4 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes4Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(Bytes4Set storage set, uint256 index) internal view returns (bytes4) {
        return bytes4(_at(set._inner, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes4Set storage set) internal view returns (bytes4[] memory) {
        bytes32[] memory store = _values(set._inner);
        bytes4[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(Bytes4Set storage set, uint256 start, uint256 end) internal view returns (bytes4[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        bytes4[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(AddressSet storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(AddressSet storage set, uint256 start, uint256 end) internal view returns (address[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        address[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(UintSet storage set) internal {
        _clear(set._inner);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(UintSet storage set) internal view returns (uint256[] memory) {
        bytes32[] memory store = _values(set._inner);
        uint256[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(UintSet storage set, uint256 start, uint256 end) internal view returns (uint256[] memory) {
        bytes32[] memory store = _values(set._inner, start, end);
        uint256[] memory result;

        assembly ("memory-safe") {
            result := store
        }

        return result;
    }

    struct StringSet {
        // Storage of set values
        string[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(string value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(StringSet storage set, string memory value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(StringSet storage set, string memory value) internal returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                string memory lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(StringSet storage set) internal {
        uint256 len = length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(StringSet storage set, string memory value) internal view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(StringSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(StringSet storage set, uint256 index) internal view returns (string memory) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(StringSet storage set) internal view returns (string[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(StringSet storage set, uint256 start, uint256 end) internal view returns (string[] memory) {
        unchecked {
            end = Math.min(end, length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            string[] memory result = new string[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }

    struct BytesSet {
        // Storage of set values
        bytes[] _values;
        // Position is the index of the value in the `values` array plus 1.
        // Position 0 is used to mean a value is not in the set.
        mapping(bytes value => uint256) _positions;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(BytesSet storage set, bytes memory value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._positions[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(BytesSet storage set, bytes memory value) internal returns (bool) {
        // We cache the value's position to prevent multiple reads from the same storage slot
        uint256 position = set._positions[value];

        if (position != 0) {
            // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 valueIndex = position - 1;
            uint256 lastIndex = set._values.length - 1;

            if (valueIndex != lastIndex) {
                bytes memory lastValue = set._values[lastIndex];

                // Move the lastValue to the index where the value to delete is
                set._values[valueIndex] = lastValue;
                // Update the tracked position of the lastValue (that was just moved)
                set._positions[lastValue] = position;
            }

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the tracked position for the deleted slot
            delete set._positions[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes all the values from a set. O(n).
     *
     * WARNING: Developers should keep in mind that this function has an unbounded cost and using it may render the
     * function uncallable if the set grows to the point where clearing it consumes too much gas to fit in a block.
     */
    function clear(BytesSet storage set) internal {
        uint256 len = length(set);
        for (uint256 i = 0; i < len; ++i) {
            delete set._positions[set._values[i]];
        }
        Arrays.unsafeSetLength(set._values, 0);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(BytesSet storage set, bytes memory value) internal view returns (bool) {
        return set._positions[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(BytesSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    /**
     * @dev Returns the value stored at position `index` in the set. O(1).
     *
     * Note that there are no guarantees on the ordering of values inside the
     * array, and it may change when more values are added or removed.
     *
     * Requirements:
     *
     * - `index` must be strictly less than {length}.
     */
    function at(BytesSet storage set, uint256 index) internal view returns (bytes memory) {
        return set._values[index];
    }

    /**
     * @dev Return the entire set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(BytesSet storage set) internal view returns (bytes[] memory) {
        return set._values;
    }

    /**
     * @dev Return a slice of the set in an array
     *
     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed
     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that
     * this function has an unbounded cost, and using it as part of a state-changing function may render the function
     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.
     */
    function values(BytesSet storage set, uint256 start, uint256 end) internal view returns (bytes[] memory) {
        unchecked {
            end = Math.min(end, length(set));
            start = Math.min(start, end);

            uint256 len = end - start;
            bytes[] memory result = new bytes[](len);
            for (uint256 i = 0; i < len; ++i) {
                result[i] = Arrays.unsafeAccess(set._values, start + i).value;
            }
            return result;
        }
    }
}

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {StakingVaultStorageLib} from "./StakingVaultStorage.sol";
import {IStakingVault} from "../interfaces/IStakingVault.sol";
import {Validator} from "gokite-contracts/contracts/validator-manager/interfaces/IACP99Manager.sol";

/**
 * @title StakingVaultInternals
 * @notice Shared internal functions for StakingVault and StakingVaultOperations
 * @dev Library functions are inlined by the compiler, so no gas overhead.
 *      These functions read from the shared ERC-7201 namespaced storage.
 */
library StakingVaultInternals {
    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get the current epoch number
     * @return epoch Current epoch based on epochStartTime and epochDuration
     */
    function getCurrentEpoch() internal view returns (uint256 epoch) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        return (block.timestamp - $.epochStartTime) / $.epochDuration;
    }

    /**
     * @notice Get total pooled stake (balance + delegated + validator stake - liabilities)
     * @return stake Total pooled stake amount
     */
    function getTotalPooledStake() internal view returns (uint256 stake) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 totalAssets = $.vaultAccountedBalance
            + $.totalDelegatedStake
            + $.totalValidatorStake;
        uint256 liabilities = $.pendingWithdrawalStake + $.totalAccruedOperatorFees
            + $.pendingProtocolFees + $.totalEscrowedWithdrawals;
        if (totalAssets > liabilities) {
            return totalAssets - liabilities;
        }
        return 0;
    }

    /**
     * @notice Get available stake (liquid balance minus reserved amounts)
     * @return stake Available stake amount
     */
    function getAvailableStake() internal view returns (uint256 stake) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 balance = $.vaultAccountedBalance;
        uint256 reserved = $.claimableWithdrawalStake + $.totalAccruedOperatorFees
            + $.pendingProtocolFees + $.totalEscrowedWithdrawals;
        if (balance > reserved) {
            return balance - reserved;
        }
        return 0;
    }

    /**
     * @notice Get minimum stake duration from the staking manager
     * @return minStakeDuration Minimum stake duration in seconds
     */
    function getMinimumStakeDuration() internal view returns (uint64 minStakeDuration) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        (bool success, bytes memory data) = address($.stakingManager).staticcall(
            abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_STAKING_MANAGER_SETTINGS)
        );
        if (!success || data.length < 128) {
            revert IStakingVault.StakingVault__StakingManagerCallFailed();
        }
        assembly {
            minStakeDuration := mload(add(data, 128))
        }
    }

    // ============================================
    // Utility Functions
    // ============================================

    /**
     * @notice Send native token to a recipient
     * @param recipient Address to send to
     * @param amount Amount to send
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert IStakingVault.StakingVault__TransferFailed();
    }

    /**
     * @notice Require address is not zero
     * @param addr Address to check
     */
    function requireNonZero(address addr) internal pure {
        if (addr == address(0)) revert IStakingVault.StakingVault__ZeroAddress();
    }

    // ============================================
    // Manager Query Helpers
    // ============================================

    /// @notice Get validator stake amount from ValidatorManager
    /// @dev Uses cached ValidatorManager address and weightToValueFactor for gas efficiency
    /// @param validationID The validator ID to query
    /// @return amount The stake amount (0 if validator not found)
    function getValidatorStakeAmountFromManager(bytes32 validationID) internal view returns (uint256 amount) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        address mgr = $.cachedValidatorManager;
        uint256 wtv = $.cachedWeightToValueFactor;
        if (mgr == address(0) || wtv == 0) return 0;

        (bool success, bytes memory data) = mgr.staticcall(
            abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_VALIDATOR, validationID)
        );
        if (!success || data.length == 0) return 0;

        // Use abi.decode for proper handling of dynamic bytes in Validator struct
        Validator memory validator = abi.decode(data, (Validator));
        amount = uint256(validator.startingWeight) * wtv;
    }

    /// @notice Get validator start time from ValidatorManager
    /// @dev Uses cached ValidatorManager address for gas efficiency
    /// @param validationID The validator ID to query
    /// @return startTime The validator start time (0 if not found)
    function getValidatorStartTimeFromManager(bytes32 validationID) internal view returns (uint64 startTime) {
        address mgr = StakingVaultStorageLib._getStorage().cachedValidatorManager;
        if (mgr == address(0)) return 0;

        (bool success, bytes memory data) = mgr.staticcall(
            abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_VALIDATOR, validationID)
        );
        if (!success || data.length == 0) return 0;

        Validator memory validator = abi.decode(data, (Validator));
        return validator.startTime;
    }

    /// @notice Get full delegator info from StakingManager in a single staticcall
    /// @dev Combines status, amount, and startTime queries. Returns success flag
    ///      to distinguish call failure from genuine Unknown(0) status.
    /// @return success True if SM call succeeded (false = skip, DON'T treat as Unknown)
    /// @return status SM delegator status (0=Unknown, 1=PendingAdded, 2=Active, 3=PendingRemoved)
    /// @return amount Delegation stake amount (weight × cachedWeightToValueFactor)
    /// @return startTime Delegation start time (0 if pending)
    function getDelegatorFullInfo(bytes32 delegationID)
        internal view
        returns (bool success, uint8 status, uint256 amount, uint64 startTime)
    {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 wtv = $.cachedWeightToValueFactor;

        bytes memory data;
        (success, data) = address($.stakingManager).staticcall(
            abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_DELEGATOR_INFO, delegationID)
        );
        if (!success || data.length < 192) {
            return (false, 0, 0, 0);
        }

        // Delegator struct layout: status(word0), owner(word1), validationID(word2), weight(word3), startTime(word4)
        uint64 weight;
        assembly {
            status := mload(add(data, 32))
            weight := mload(add(data, 128))
            startTime := mload(add(data, 160))
        }
        if (wtv > 0) {
            amount = uint256(weight) * wtv;
        }
    }

    /// @notice Get validator status from ValidatorManager
    /// @dev Status values: 0=Unknown, 1=PendingAdded, 2=Active, 3=PendingRemoved, 4=Completed, 5=Invalidated
    ///      After completeValidatorRemoval, status becomes 4 (Completed) or 5 (Invalidated)
    ///      Validator data (including weight) is preserved even after completion
    /// @param validationID The validation ID to query
    /// @return status The validator status (0 if not found)
    function getValidatorStatusFromManager(bytes32 validationID) internal view returns (uint8 status) {
        address mgr = StakingVaultStorageLib._getStorage().cachedValidatorManager;
        if (mgr == address(0)) return 0;

        (bool success, bytes memory data) = mgr.staticcall(
            abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_VALIDATOR, validationID)
        );
        if (!success || data.length == 0) return 0;

        Validator memory validator = abi.decode(data, (Validator));
        return uint8(validator.status);
    }
}

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {IKiteStakingManager} from "gokite-contracts/contracts/validator-manager/interfaces/IKiteStakingManager.sol";
import {IStakingVault} from "../interfaces/IStakingVault.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title StakingVaultStorageLib
 * @notice Shared storage library for StakingVault and StakingVaultOperations
 * @dev Uses ERC-7201 namespaced storage pattern for upgrade safety.
 *      Both main contract and extension contract use identical storage layout.
 */
library StakingVaultStorageLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ============================================
    // Storage Slot Constants (ERC-7201)
    // ============================================

    // keccak256(abi.encode(uint256(keccak256("stakingvault.storage.main")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant STAKING_VAULT_STORAGE_LOCATION =
        0xe89bc2f435ba7b383b8efac5edfc2f023d18edcd77b8a1b95b1375c9045b1400;

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant REENTRANCY_GUARD_STORAGE =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    // ============================================
    // Reentrancy Guard Constants
    // ============================================

    uint256 internal constant NOT_ENTERED = 1;
    uint256 internal constant ENTERED = 2;

    // ============================================
    // Protocol Constants
    // ============================================

    /// @notice Virtual offset to prevent first depositor attack
    uint256 internal constant INITIAL_SHARES_OFFSET = 1e9;

    /// @notice Maximum protocol fee (20%)
    uint256 internal constant MAX_PROTOCOL_FEE_BIPS = 2000;

    /// @notice Maximum operator fee (20%)
    uint256 internal constant MAX_OPERATOR_FEE_BIPS = 2000;

    /// @notice Bips conversion factor
    uint256 internal constant BIPS_DENOMINATOR = 10_000;

    /// @notice Default maximum number of operators
    uint256 internal constant DEFAULT_MAX_OPERATORS = 10;

    /// @notice Default maximum validators per operator
    uint256 internal constant DEFAULT_MAX_VALIDATORS_PER_OPERATOR = 20;

    /// @notice Maximum withdrawal request fee (1 ether)
    uint256 internal constant MAX_WITHDRAWAL_REQUEST_FEE = 1 ether;

    /// @notice Maximum successful removal initiations per call (gas safety)
    uint256 internal constant MAX_REMOVALS_PER_CALL = 50;

    /// @notice Maximum delegation scans per call across all operators (gas safety)
    uint256 internal constant MAX_DELEGATION_SCAN_PER_CALL = 300;

    /// @notice Maximum validator scans per call across all operators (gas safety)
    uint256 internal constant MAX_VALIDATOR_SCAN_PER_CALL = 200;

    /// @notice Maximum fulfilled queue entries advanced per call (gas safety)
    uint256 internal constant MAX_ADVANCE_PER_CALL = 50;

    /// @notice Maximum withdrawal queue entries processed per processEpoch call (gas safety)
    uint256 internal constant MAX_PROCESS_PER_CALL = 350;

    /// @notice Debt threshold (50% of operator's allocation) above which new stake deployment is frozen
    /// @dev When an operator fails to meet their share of withdrawal liquidity (exit debt), they accumulate debt.
    ///      If debt exceeds 50% of their allocation's share of the pool, they cannot deploy new stake until
    ///      the debt is reduced. This prevents operators from deploying while significantly underwater,
    ///      ensuring they first restore liquidity before taking on new positions.
    uint256 internal constant DEBT_FREEZE_THRESHOLD_BIPS = 5000;

    // ============================================
    // Role Constants
    // ============================================

    /// @notice Role for operator management (add/remove operators, update allocations)
    bytes32 internal constant OPERATOR_MANAGER_ROLE = keccak256("OPERATOR_MANAGER_ROLE");

    /// @notice Role for vault administration (fees, pause, force-removal)
    bytes32 internal constant VAULT_ADMIN_ROLE = keccak256("VAULT_ADMIN_ROLE");

    // ============================================
    // Selector Constants
    // ============================================

    /// @notice Selector for StakingManager.getStakingValidator(bytes32)
    bytes4 internal constant SEL_GET_STAKING_VALIDATOR = bytes4(keccak256("getStakingValidator(bytes32)"));

    /// @notice Selector for StakingManager.claimValidatorRewards(bytes32,bool,uint32)
    bytes4 internal constant SEL_CLAIM_VALIDATOR_REWARDS =
        bytes4(keccak256("claimValidatorRewards(bytes32,bool,uint32)"));

    /// @notice Selector for StakingManager.claimDelegatorRewards(bytes32,bool,uint32)
    bytes4 internal constant SEL_CLAIM_DELEGATOR_REWARDS =
        bytes4(keccak256("claimDelegatorRewards(bytes32,bool,uint32)"));

    /// @notice Selector for StakingManager.forceInitiateDelegatorRemoval(bytes32,bool,uint32)
    bytes4 internal constant SEL_FORCE_INITIATE_DELEGATOR_REMOVAL =
        bytes4(keccak256("forceInitiateDelegatorRemoval(bytes32,bool,uint32)"));

    /// @notice Selector for StakingManager.forceInitiateValidatorRemoval(bytes32,bool,uint32)
    bytes4 internal constant SEL_FORCE_INITIATE_VALIDATOR_REMOVAL =
        bytes4(keccak256("forceInitiateValidatorRemoval(bytes32,bool,uint32)"));

    /// @notice Selector for StakingManager.getStakingManagerSettings()
    bytes4 internal constant SEL_GET_STAKING_MANAGER_SETTINGS = bytes4(keccak256("getStakingManagerSettings()"));

    /// @notice Selector for ValidatorManager.getValidator(bytes32)
    bytes4 internal constant SEL_GET_VALIDATOR = bytes4(keccak256("getValidator(bytes32)"));

    /// @notice Selector for StakingManager.getDelegatorInfo(bytes32)
    bytes4 internal constant SEL_GET_DELEGATOR_INFO = bytes4(keccak256("getDelegatorInfo(bytes32)"));

    // ============================================
    // Storage Structs
    // ============================================

    /// @custom:storage-location erc7201:stakingvault.storage.main
    struct StakingVaultStorage {
        /// External StakingManager contract reference
        IKiteStakingManager stakingManager;
        /// Operator address → Operator struct
        mapping(address => IStakingVault.Operator) operators;
        /// Set of all operator addresses
        EnumerableSet.AddressSet operatorSet;
        /// Validator ID → owning operator address
        mapping(bytes32 => address) validatorToOperator;
        /// Validator ID → whether removal has been initiated
        mapping(bytes32 => bool) validatorPendingRemoval;
        /// Ordered withdrawal request queue
        IStakingVault.WithdrawalRequest[] withdrawalQueue;
        /// Index of the first unprocessed queue entry
        uint256 queueHead;
        /// Duration of each epoch in seconds
        uint256 epochDuration;
        /// Timestamp when the first epoch started
        uint256 epochStartTime;
        /// Last epoch number that was processed
        uint256 lastEpochProcessed;
        /// Total stake amount in pending (not yet claimable) withdrawals
        uint256 pendingWithdrawalStake;
        /// Total stake reserved for claimable withdrawals
        uint256 claimableWithdrawalStake;
        /// Request ID → whether the withdrawal is claimable
        mapping(uint256 => bool) withdrawalClaimable;
        /// Total stake currently delegated via StakingManager
        uint256 totalDelegatedStake;
        /// Protocol fee in basis points
        uint256 protocolFeeBips;
        /// Address receiving protocol fees
        address protocolFeeRecipient;
        /// Liquidity buffer ratio in basis points
        uint256 liquidityBufferBips;
        /// Sum of all operators' accrued but unclaimed fees
        uint256 totalAccruedOperatorFees;
        /// Vault-level operator fee (delegation fee for vault-owned validators, fee taken on delegation harvests)
        uint256 operatorFeeBips;
        /// Total stake sent to validators via initiateValidatorRegistration
        uint256 totalValidatorStake;
        // ============================================
        // Unified Delegation System
        // ============================================
        /// Operator address → set of delegation IDs
        mapping(address => EnumerableSet.Bytes32Set) operatorDelegations;
        /// Delegation ID → DelegatorInfo metadata
        mapping(bytes32 => IStakingVault.DelegatorInfo) delegatorInfo;
        /// Operator address → set of validator IDs
        mapping(address => EnumerableSet.Bytes32Set) operatorValidators;
        // ============================================
        // Proportional Withdrawal Selection
        // ============================================
        /// Operator address → accumulated exit debt
        mapping(address => uint256) operatorExitDebt;
        /// Sum of all operators' exit debt
        uint256 totalExitDebt;
        /// Total stake in delegations/validators pending removal
        uint256 inFlightExitingAmount;
        /// Operator address → removal amount credited from prior epochs
        mapping(address => uint256) operatorPriorEpochPendingAmount;
        /// Operator address → removal amount recorded in the current epoch
        mapping(address => uint256) operatorCurrentEpochPendingAmount;
        /// Last epoch when pending amounts were reconciled
        uint256 lastPendingReconcileEpoch;
        /// Delegation ID → epoch+1 when removal was initiated (0 = unset)
        mapping(bytes32 => uint256) delegatorRemovalInitiatedEpoch;
        /// Validator ID → epoch+1 when removal was initiated (0 = unset)
        mapping(bytes32 => uint256) validatorRemovalInitiatedEpoch;
        /// @notice Delegation principal (stake amount recorded at registration)
        /// @dev Set once during initiateDelegatorRegistration. Used for all vault accounting.
        ///      Required because StakingManager clears delegator weight after completeDelegatorRemoval.
        mapping(bytes32 => uint256) delegationPrincipal;
        // ============================================
        // Maximum Stake Limits
        // ============================================
        /// @notice Maximum stake amount per validator registration (type(uint256).max = unlimited)
        uint256 maximumValidatorStake;
        /// @notice Maximum stake amount per delegator registration (type(uint256).max = unlimited)
        uint256 maximumDelegatorStake;
        // ============================================
        // Protocol Fee Escrow
        // ============================================
        /// @notice Protocol fees escrowed when protocolFeeRecipient reverts
        uint256 pendingProtocolFees;
        // ============================================
        // Operations Extension
        // ============================================
        /// Address of the StakingVaultOperations implementation
        address operationsImpl;
        // ============================================
        // Cached Immutable Values (from StakingManager)
        // ============================================
        /// @notice Cached ValidatorManager address (immutable after StakingManager init)
        address cachedValidatorManager;
        /// @notice Cached weightToValueFactor (immutable after StakingManager init)
        uint256 cachedWeightToValueFactor;
        // ============================================
        // processEpoch Scan Cursor
        // ============================================
        /// @notice Cursor for processEpoch to skip already-claimable entries
        uint256 queueProcessHead;
        // ============================================
        // Configurable Limits
        // ============================================
        /// @notice Maximum number of operators (admin-configurable, default 10)
        uint256 maxOperators;
        /// @notice Maximum validators per operator (admin-configurable, default 20)
        uint256 maxValidatorsPerOperator;
        // ============================================
        // Withdrawal Escrow
        // ============================================
        /// @notice Per-user escrowed withdrawal amounts (escrowed when recipient reverts)
        mapping(address => uint256) withdrawalEscrow;
        /// @notice Total escrowed withdrawals (reserved in balance calculations)
        uint256 totalEscrowedWithdrawals;
        /// @notice Validator principal (stake amount recorded at registration)
        /// @dev Set once during initiateValidatorRegistration. Used for all vault accounting.
        ///      Required because getValidatorStakeAmountFromManager can fail (gas starvation, broken VM).
        ///      Mirrors delegationPrincipal for delegators.
        mapping(bytes32 => uint256) validatorPrincipal;
        /// @notice Vault-internal tracked balance for share pricing
        /// @dev Only incremented/decremented by vault functions. External inflows (untracked manager
        ///      completions, donations, selfdestruct) increase address(this).balance but NOT this field,
        ///      preventing share price inflation. Used in getTotalPooledStake() and getAvailableStake()
        ///      (and processEpoch via getAvailableStake). address(this).balance is used only for the
        ///      actual .call{value} transfer to spend any forced-in tokens.
        uint256 vaultAccountedBalance;
        /// @notice Transient gate for receiving native token from StakingManager inflow calls.
        bool isReceivingManagerFunds;
        /// @notice Epoch number of the most recent withdrawal request (for O(1) pending demand)
        uint256 currentEpochWithdrawalEpoch;
        /// @notice Sum of stakeAmounts requested in currentEpochWithdrawalEpoch
        uint256 currentEpochWithdrawalAmount;
        /// @notice Flat fee deducted from each withdrawal request's stakeAmount (anti-spam)
        uint256 withdrawalRequestFee;
    }

    /// @dev Context for delegation removal selection (used to avoid stack-too-deep)
    struct RemovalContext {
        address[] activeOperators;
        uint256[] targetShares;
        uint256 activeCount;
        uint256 effectiveNeeded;
        uint256 totalAllocationBips;
        uint64 maturityCutoff;
    }

    // ============================================
    // Storage Access
    // ============================================

    /// @dev Returns the main storage pointer using ERC-7201 namespaced slot.
    function _getStorage() internal pure returns (StakingVaultStorage storage $) {
        assembly {
            $.slot := STAKING_VAULT_STORAGE_LOCATION
        }
    }

    // ============================================
    // Reentrancy Guard Functions
    // ============================================

    /// @dev Sets reentrancy guard to entered state; reverts if already entered.
    function _nonReentrantBefore() internal {
        uint256 status;
        bytes32 slot = REENTRANCY_GUARD_STORAGE;
        assembly {
            status := sload(slot)
        }
        if (status == ENTERED) {
            revert IStakingVault.StakingVault__ReentrancyGuardReentrantCall();
        }
        assembly {
            sstore(slot, ENTERED)
        }
    }

    /// @dev Resets reentrancy guard to not-entered state.
    function _nonReentrantAfter() internal {
        bytes32 slot = REENTRANCY_GUARD_STORAGE;
        assembly {
            sstore(slot, NOT_ENTERED)
        }
    }

    /// @dev Initializes the reentrancy guard to not-entered state.
    function __ReentrancyGuard_init() internal {
        bytes32 slot = REENTRANCY_GUARD_STORAGE;
        assembly {
            sstore(slot, NOT_ENTERED)
        }
    }
}

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

/**
 * @title IStakingVault
 * @notice Interface for the StakingVault liquid staking contract (main contract)
 * @dev Operations functions (validators, delegations, admin config) are in IStakingVaultOperations
 */
interface IStakingVault {
    // ============================================
    // Structs
    // ============================================

    struct Operator {
        bool active;
        uint256 allocationBips;
        uint256 activeStake;
        uint256 accruedFees;
        address feeRecipient;
    }

    struct WithdrawalRequest {
        address user;
        uint256 shares;
        uint256 stakeAmount;
        uint256 requestEpoch;
        bool fulfilled;
    }

    /// @notice Unified delegator metadata for both internal and external delegators
    /// @dev amount and startTime are fetched from StakingManager
    struct DelegatorInfo {
        bytes32 validationID; // Target validator (kept for SM lookups)
        address operator; // Operator who created the delegation (vault-specific)
        bool isVaultOwnedValidator; // True if validator is vault-owned (for harvest routing)
    }

    // ============================================
    // Errors
    // ============================================

    error StakingVault__ZeroAddress();
    error StakingVault__InvalidAmount();
    error StakingVault__InvalidFee(uint256 fee);
    error StakingVault__InvalidEpochDuration();
    error StakingVault__InvalidImplementation(address implementation);
    error StakingVault__ReentrancyGuardReentrantCall();

    error StakingVault__InsufficientBalance(uint256 requested, uint256 available);
    error StakingVault__InsufficientBuffer();

    error StakingVault__WithdrawalNotClaimable(uint256 requestId);
    error StakingVault__WithdrawalNotFound(uint256 requestId);
    error StakingVault__WithdrawalAlreadyClaimed(uint256 requestId);
    error StakingVault__EpochNotEnded();

    error StakingVault__NotOperator(address caller);
    error StakingVault__NotOperatorManager(address caller);
    error StakingVault__OperatorNotActive(address operator);
    error StakingVault__OperatorAlreadyExists(address operator);
    error StakingVault__OperatorHasActiveValidators(address operator);
    error StakingVault__OperatorHasDelegators(address operator);
    error StakingVault__OperatorHasUnclaimedFees(address operator);
    error StakingVault__InvalidOperatorIndex(uint256 index);
    error StakingVault__AllocationExceeded(uint256 total);
    error StakingVault__LimitExceeded();
    error StakingVault__ExceedsOperatorAllocation(address operator, uint256 requested, uint256 available);

    error StakingVault__ValidatorNotOwnedByOperator(bytes32 validationID, address operator);
    error StakingVault__ValidatorPendingRemoval(bytes32 validationID);
    error StakingVault__ValidatorNotFound(bytes32 validationID);
    error StakingVault__NoEligibleStake();
    error StakingVault__DelegationFeeTooHigh(uint16 actual, uint16 maxAllowed);
    error StakingVault__ExternalValidatorNotFound(bytes32 validationID);
    error StakingVault__MinStakeDurationMismatch(uint64 validatorDuration, uint64 requiredDuration);
    error StakingVault__NotDelegatorOperator(bytes32 delegationID, address caller);
    error StakingVault__DelegatorNotFound(bytes32 delegationID);
    error StakingVault__DelegatorAlreadyPendingRemoval(bytes32 delegationID);
    error StakingVault__DelegatorIncomplete(bytes32 delegationID);
    error StakingVault__SlippageExceeded(uint256 actual, uint256 minExpected);
    error StakingVault__OperatorDebtTooHigh(address operator, uint256 currentDebt);
    error StakingVault__TransferFailed();
    error StakingVault__ArrayLengthMismatch();
    error StakingVault__NoFeesToClaim();
    error StakingVault__NoEscrowedWithdrawal();
    error StakingVault__InvalidFeeRecipient();
    error StakingVault__InvalidStakingManager();
    error StakingVault__StakingManagerCallFailed();
    error StakingVault__StakeExceedsMaximum(uint256 amount, uint256 maximum);
    error StakingVault__NonTransferable();
    error StakingVault__UnauthorizedReceive();
    error StakingVault__Insolvent();

    // ============================================
    // Events
    // ============================================

    /**
     * @notice Emitted when a user deposits native token and receives shares.
     * @param user Address of the depositor
     * @param stakeAmount Amount of native token deposited
     * @param shares Amount of shares minted
     */
    event StakingVault__Deposited(address indexed user, uint256 stakeAmount, uint256 shares);

    /**
     * @notice Emitted when a user requests a withdrawal.
     * @param user Address of the user requesting withdrawal
     * @param requestId ID of the withdrawal request
     * @param shares Amount of shares burned
     * @param stakeAmount Amount of native token to be withdrawn
     */
    event StakingVault__WithdrawalRequested(
        address indexed user, uint256 requestId, uint256 shares, uint256 stakeAmount
    );

    /**
     * @notice Emitted when a user claims their withdrawal.
     * @param user Address of the user claiming
     * @param requestId ID of the withdrawal request
     * @param stakeAmount Amount of native token claimed
     */
    event StakingVault__WithdrawalClaimed(address indexed user, uint256 requestId, uint256 stakeAmount);

    /**
     * @notice Emitted when an epoch is processed.
     * @param epoch The epoch number that was processed
     * @param withdrawalsFulfilled Number of withdrawal requests fulfilled
     * @param stakeReleased Amount of native token released to claimable
     * @param requestsRemaining Number of requests remaining in queue
     */
    event StakingVault__EpochProcessed(
        uint256 indexed epoch, uint256 withdrawalsFulfilled, uint256 stakeReleased, uint256 requestsRemaining
    );

    /**
     * @notice Emitted when the operations implementation address is updated.
     * @param oldImpl Previous operations implementation address
     * @param newImpl New operations implementation address
     */
    event StakingVault__OperationsImplUpdated(address indexed oldImpl, address indexed newImpl);

    /**
     * @notice Emitted when the protocol fee is updated.
     * @param oldFee Previous protocol fee in basis points
     * @param newFee New protocol fee in basis points
     */
    event StakingVault__ProtocolFeeUpdated(uint256 oldFee, uint256 newFee);

    /**
     * @notice Emitted when the protocol fee recipient is updated.
     * @param oldRecipient Previous fee recipient address
     * @param newRecipient New fee recipient address
     */
    event StakingVault__ProtocolFeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    /**
     * @notice Emitted when the liquidity buffer ratio is updated.
     * @param oldBips Previous buffer ratio in basis points
     * @param newBips New buffer ratio in basis points
     */
    event StakingVault__LiquidityBufferUpdated(uint256 oldBips, uint256 newBips);

    /**
     * @notice Emitted when the operator fee is updated.
     * @param oldFee Previous operator fee in basis points
     * @param newFee New operator fee in basis points
     */
    event StakingVault__OperatorFeeUpdated(uint256 oldFee, uint256 newFee);

    /**
     * @notice Emitted when the maximum validator stake is updated.
     * @param oldMax Previous maximum stake
     * @param newMax New maximum stake
     */
    event StakingVault__MaximumValidatorStakeUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @notice Emitted when the maximum delegator stake is updated.
     * @param oldMax Previous maximum stake
     * @param newMax New maximum stake
     */
    event StakingVault__MaximumDelegatorStakeUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @notice Emitted when the maximum number of operators is updated.
     * @param oldMax Previous maximum
     * @param newMax New maximum
     */
    event StakingVault__MaxOperatorsUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @notice Emitted when the maximum validators per operator is updated.
     * @param oldMax Previous maximum
     * @param newMax New maximum
     */
    event StakingVault__MaxValidatorsPerOperatorUpdated(uint256 oldMax, uint256 newMax);

    /**
     * @notice Emitted when the withdrawal request fee is updated.
     * @param oldFee Previous withdrawal request fee
     * @param newFee New withdrawal request fee
     */
    event StakingVault__WithdrawalRequestFeeUpdated(uint256 oldFee, uint256 newFee);

    /**
     * @notice Emitted when pending protocol fees are claimed by admin.
     * @param amount Amount of fees claimed
     */
    event StakingVault__PendingProtocolFeesClaimed(uint256 amount);

    /**
     * @notice Emitted when a withdrawal is escrowed because the recipient reverted.
     * @param user Address of the withdrawal recipient
     * @param requestId ID of the withdrawal request
     * @param amount Amount escrowed
     */
    event StakingVault__WithdrawalEscrowed(address indexed user, uint256 requestId, uint256 amount);

    /**
     * @notice Emitted when a user claims their escrowed withdrawal.
     * @param user Address of the user who had escrowed native token
     * @param recipient Address that received the native token
     * @param amount Amount claimed
     */
    event StakingVault__EscrowedWithdrawalClaimed(address indexed user, address indexed recipient, uint256 amount);

    // ============================================
    // User Functions
    // ============================================

    /**
     * @notice Deposit native token and receive LST.
     * @param minShares Minimum shares to receive (slippage protection, 0 to skip check)
     * @return shares Amount of LST minted
     */
    function deposit(
        uint256 minShares
    ) external payable returns (uint256 shares);

    /**
     * @notice Request withdrawal (burns LST immediately).
     * @param shares Amount of LST to burn
     * @return requestId ID of the withdrawal request
     */
    function requestWithdrawal(
        uint256 shares
    ) external returns (uint256 requestId);

    /**
     * @notice Claim fulfilled withdrawal.
     * @dev If the native token transfer to the recipient reverts, the amount is escrowed.
     *      The user can later call `claimEscrowedWithdrawal(recipient)` to redirect to a working address.
     * @param requestId ID of the withdrawal request
     */
    function claimWithdrawal(
        uint256 requestId
    ) external;

    /**
     * @notice Claim a fulfilled withdrawal on behalf of the request owner.
     * @dev Anyone can call. Native token is sent to the original request owner.
     * @param requestId ID of the withdrawal request
     */
    function claimWithdrawalFor(
        uint256 requestId
    ) external;

    /**
     * @notice Batch claim multiple fulfilled withdrawals.
     * @dev Requires msg.sender == request.user for each request. If any individual native token
     *      transfer fails, the amount is escrowed for the recipient rather than reverting the batch.
     * @param requestIds Array of withdrawal request IDs to claim
     */
    function claimWithdrawals(
        uint256[] calldata requestIds
    ) external;

    /**
     * @notice Batch claim multiple fulfilled withdrawals on behalf of the request owners.
     * @dev Anyone can call. Native token is sent to the original request owner for each. If any individual
     *      native token transfer fails, the amount is escrowed for the recipient rather than reverting the batch.
     * @param requestIds Array of withdrawal request IDs to claim
     */
    function claimWithdrawalsFor(
        uint256[] calldata requestIds
    ) external;

    /**
     * @notice Get current exchange rate.
     * @return rate 1 LST = rate native token (scaled by 1e18)
     */
    function getExchangeRate() external view returns (uint256 rate);

    // ============================================
    // Lifecycle Functions
    // ============================================

    /**
     * @notice Initialize the StakingVault contract.
     * @param _stakingManager Address of the StakingManager contract
     * @param _protocolFeeRecipient Address to receive protocol fees
     * @param _operatorManager Address of the operator manager (OPERATOR_MANAGER_ROLE)
     * @param _protocolFeeBips Protocol fee in basis points
     * @param _epochDuration Duration of each epoch in seconds
     * @param _liquidityBufferBips Percentage of total pooled stake to keep liquid for withdrawal processing
     * @param _defaultAdmin Address for DEFAULT_ADMIN_ROLE (upgrades, role management)
     * @param _vaultAdmin Address for VAULT_ADMIN_ROLE (fees, pause, force-removal)
     * @param _defaultAdminDelay Delay in seconds for 2-step admin transfers (e.g., 3600 for 1 hour)
     * @param _name Token name for the LST
     * @param _symbol Token symbol for the LST
     * @param _operationsImpl Address of the StakingVaultOperations implementation contract
     */
    function initialize(
        address _stakingManager,
        address _protocolFeeRecipient,
        address _operatorManager,
        uint256 _protocolFeeBips,
        uint256 _epochDuration,
        uint256 _liquidityBufferBips,
        address _defaultAdmin,
        address _vaultAdmin,
        uint48 _defaultAdminDelay,
        string memory _name,
        string memory _symbol,
        address _operationsImpl
    ) external;

    /**
     * @notice Set the operations implementation address.
     * @param _operationsImpl New operations implementation address
     */
    function setOperationsImpl(
        address _operationsImpl
    ) external;

    /**
     * @notice Get the operations implementation address.
     * @return impl Address of the operations implementation
     */
    function getOperationsImpl() external view returns (address impl);

    /**
     * @notice Pause deposits and withdrawal requests.
     */
    function pause() external;

    /**
     * @notice Unpause deposits and withdrawal requests.
     */
    function unpause() external;

    /**
     * @notice Process current epoch's withdrawals (can be called by anyone after epoch ends).
     * @return finished True if the epoch is fully processed; false if the scan cap was hit or
     *         liquidity was exhausted, and another call is needed to continue processing.
     */
    function processEpoch() external returns (bool finished);

    // ============================================
    // Admin Configuration
    // ============================================

    /**
     * @notice Set the protocol fee in basis points.
     * @param bips New protocol fee (must not exceed MAX_PROTOCOL_FEE_BIPS)
     */
    function setProtocolFeeBips(
        uint256 bips
    ) external;

    /**
     * @notice Set the protocol fee recipient address.
     * @param _protocolFeeRecipient New fee recipient (must not be zero address)
     */
    function setProtocolFeeRecipient(
        address _protocolFeeRecipient
    ) external;

    /**
     * @notice Set the liquidity buffer ratio in basis points.
     * @param _liquidityBufferBips New buffer ratio (must not exceed BIPS_DENOMINATOR)
     */
    function setLiquidityBufferBips(
        uint256 _liquidityBufferBips
    ) external;

    /**
     * @notice Set the vault-level operator fee in basis points.
     * @param bips New operator fee (must not exceed MAX_OPERATOR_FEE_BIPS)
     */
    function setOperatorFeeBips(
        uint256 bips
    ) external;

    /**
     * @notice Set the maximum stake per validator registration.
     * @param amount New maximum (type(uint256).max for unlimited)
     */
    function setMaximumValidatorStake(
        uint256 amount
    ) external;

    /**
     * @notice Set the maximum stake per delegator registration.
     * @param amount New maximum (type(uint256).max for unlimited)
     */
    function setMaximumDelegatorStake(
        uint256 amount
    ) external;

    /**
     * @notice Set the maximum number of operators.
     * @param newMax New maximum (must be > 0)
     */
    function setMaxOperators(
        uint256 newMax
    ) external;

    /**
     * @notice Set the maximum validators per operator.
     * @param newMax New maximum (must be > 0)
     */
    function setMaxValidatorsPerOperator(
        uint256 newMax
    ) external;

    /**
     * @notice Set the flat fee deducted from each withdrawal request.
     * @param fee New withdrawal request fee (0 = no fee, max MAX_WITHDRAWAL_REQUEST_FEE)
     */
    function setWithdrawalRequestFee(
        uint256 fee
    ) external;

    /**
     * @notice Claim escrowed withdrawal native token that was held when the recipient reverted.
     * @dev Allows reverting contracts to redirect native token to an EOA.
     * @param recipient Address to send the escrowed native token to (must not be zero)
     */
    function claimEscrowedWithdrawal(
        address recipient
    ) external;

    /**
     * @notice Claim escrowed protocol fees that accumulated when the recipient reverted.
     */
    function claimPendingProtocolFees() external;

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get total pooled stake (balance + delegated - pending withdrawals).
     * @return stake Total pooled stake amount
     */
    function getTotalPooledStake() external view returns (uint256 stake);

    /**
     * @notice Get available stake (liquid balance minus claimable withdrawals).
     * @return stake Available stake amount
     */
    function getAvailableStake() external view returns (uint256 stake);

    /**
     * @notice Get escrowed protocol fees pending claim.
     * @return fees Pending protocol fees
     */
    function getPendingProtocolFees() external view returns (uint256 fees);

    /**
     * @notice Get total pending withdrawals.
     * @return amount Total pending withdrawal amount
     */
    function getPendingWithdrawals() external view returns (uint256 amount);

    /**
     * @notice Get the current epoch number.
     * @return epoch Current epoch
     */
    function getCurrentEpoch() external view returns (uint256 epoch);

    /**
     * @notice Get the epoch duration.
     * @return duration Epoch duration in seconds
     */
    function getEpochDuration() external view returns (uint256 duration);

    /**
     * @notice Get the epoch start time (set at initialization).
     * @return startTime Epoch start timestamp
     */
    function getStartTime() external view returns (uint256 startTime);

    /**
     * @notice Get operator information.
     * @param operator Address of the operator
     * @return info Operator struct with all operator data
     */
    function getOperatorInfo(
        address operator
    ) external view returns (Operator memory info);

    /**
     * @notice Get withdrawal request details.
     * @param requestId ID of the withdrawal request
     * @return request WithdrawalRequest struct with request data
     */
    function getWithdrawalRequest(
        uint256 requestId
    ) external view returns (WithdrawalRequest memory request);

    /**
     * @notice Get the staking manager address.
     * @return manager Address of the staking manager
     */
    function getStakingManager() external view returns (address manager);

    /**
     * @notice Get the protocol fee recipient address.
     * @return recipient Address of the protocol fee recipient
     */
    function getProtocolFeeRecipient() external view returns (address recipient);

    /**
     * @notice Get the protocol fee in basis points.
     * @return bips Protocol fee in bips
     */
    function getProtocolFeeBips() external view returns (uint256 bips);

    /**
     * @notice Get the liquidity buffer ratio in basis points.
     * @dev Percentage of total pooled stake to keep liquid for withdrawal processing
     * @return bips Liquidity buffer ratio in bips
     */
    function getLiquidityBufferBips() external view returns (uint256 bips);

    /**
     * @notice Get the vault-level operator fee in basis points.
     * @dev Used as delegation fee for vault-owned validators and for fee calculations on delegation harvests
     * @return bips Operator fee in bips
     */
    function getOperatorFeeBips() external view returns (uint256 bips);

    /**
     * @notice Get the total delegated stake.
     * @return stake Total delegated stake amount
     */
    function getTotalDelegatedStake() external view returns (uint256 stake);

    /**
     * @notice Get list of all operators.
     * @return operators Array of operator addresses
     */
    function getOperatorList() external view returns (address[] memory operators);

    /**
     * @notice Get the withdrawal queue head position.
     * @return index Queue head index
     */
    function getQueueHead() external view returns (uint256 index);

    /**
     * @notice Get the total number of withdrawal requests ever created.
     * @dev The active queue spans from getQueueHead() to getWithdrawalQueueLength() - 1.
     * @return length Total withdrawal queue length (includes fulfilled/deleted entries)
     */
    function getWithdrawalQueueLength() external view returns (uint256 length);

    /**
     * @notice Get all active withdrawal request IDs for a given user.
     * @dev O(active queue size): iterates the full active queue twice. The queue is unbounded
     *      (no hard cap); large queues can exceed block gas limits or eth_call caps. Intended
     *      for off-chain clients. On-chain callers or clients with large queues should use
     *      getQueueHead(), getWithdrawalQueueLength(), and getWithdrawalRequest(id) for
     *      paginated access.
     * @param user The address to query withdrawal requests for
     * @return requestIds Array of request IDs belonging to the user
     */
    function getWithdrawalRequestIds(
        address user
    ) external view returns (uint256[] memory requestIds);

    /**
     * @notice Get the last processed epoch.
     * @return epoch Last epoch processed
     */
    function getLastEpochProcessed() external view returns (uint256 epoch);

    /**
     * @notice Check if a validator is pending removal.
     * @param validationID The validator ID to check
     * @return pending True if the validator is pending removal
     */
    function isValidatorPendingRemoval(
        bytes32 validationID
    ) external view returns (bool pending);

    /**
     * @notice Get the minimum stake duration from the staking manager.
     * @dev Reads directly from StakingManager's settings.
     * @return duration Minimum stake duration in seconds
     */
    function getMinimumStakeDuration() external view returns (uint64 duration);

    /**
     * @notice Get all delegators for an operator.
     * @dev Gas warning: copies the entire EnumerableSet into memory. With many delegations
     *      this may exceed block gas limits for on-chain callers or `eth_call` time/gas caps.
     *      Off-chain clients can use event indexing for unbounded access.
     * @param operatorAddr Address of the operator
     * @return delegationIDs Array of delegation IDs
     */
    function getOperatorDelegators(
        address operatorAddr
    ) external view returns (bytes32[] memory delegationIDs);

    /**
     * @notice Get all validators for an operator.
     * @param operatorAddr Address of the operator
     * @return validatorIDs Array of validation IDs
     */
    function getOperatorValidators(
        address operatorAddr
    ) external view returns (bytes32[] memory validatorIDs);

    /**
     * @notice Get delegator info for a specific delegation.
     * @param delegationID ID of the delegation
     * @return info DelegatorInfo struct with delegation data
     */
    function getDelegatorInfo(
        bytes32 delegationID
    ) external view returns (DelegatorInfo memory info);

    // ============================================
    // ERC-7540 Compatible View Functions
    // ============================================

    /**
     * @notice Get total claimable stake (reserved for claims).
     * @return stake Total claimable stake amount
     */
    function getClaimableWithdrawalStake() external view returns (uint256 stake);

    /**
     * @notice Check if a specific withdrawal request is claimable.
     * @param requestId ID of the withdrawal request
     * @return claimable True if the withdrawal can be claimed
     */
    function isWithdrawalClaimable(
        uint256 requestId
    ) external view returns (bool claimable);

    /**
     * @notice Get total pending (not yet claimable) stake for an owner.
     * @dev ERC-7540 compatible: equivalent to pendingRedeemRequest.
     *      O(active queue size): scans the full active queue. Use paginated primitives for
     *      large queues.
     * @param owner_ Address of the owner
     * @return pendingStake Total pending stake amount
     */
    function pendingRedeemRequest(
        address owner_
    ) external view returns (uint256 pendingStake);

    /**
     * @notice Get total claimable stake for an owner.
     * @dev ERC-7540 compatible: equivalent to claimableRedeemRequest.
     *      O(active queue size): scans the full active queue. Use paginated primitives for
     *      large queues.
     * @param owner_ Address of the owner
     * @return claimableStake Total claimable stake amount
     */
    function claimableRedeemRequest(
        address owner_
    ) external view returns (uint256 claimableStake);

    // ============================================
    // Accounting Tracking View Functions
    // ============================================

    /**
     * @notice Get total accrued operator fees (liability not backing shares).
     * @return fees Total operator fees that have been accrued but not yet claimed
     */
    function getTotalAccruedOperatorFees() external view returns (uint256 fees);

    /**
     * @notice Get total validator staked amount (asset tracked separately).
     * @return stake Total stake sent to validators via initiateValidatorRegistration
     */
    function getTotalValidatorStake() external view returns (uint256 stake);

    /**
     * @notice Get the stake amount for a specific validator.
     * @param validationID The validator ID to query
     * @return amount The amount staked to this validator
     */
    function getValidatorStakeAmount(
        bytes32 validationID
    ) external view returns (uint256 amount);

    // ============================================
    // Proportional Withdrawal Selection View Functions
    // ============================================

    /**
     * @notice Get the exit debt for a specific operator.
     * @param operator Address of the operator
     * @return debt The operator's current exit debt
     */
    function getOperatorExitDebt(
        address operator
    ) external view returns (uint256 debt);

    /**
     * @notice Get the total exit debt across all operators.
     * @return debt Total exit debt
     */
    function getTotalExitDebt() external view returns (uint256 debt);

    /**
     * @notice Get the total in-flight exiting amount.
     * @return amount Total amount in delegations/validators pending removal
     */
    function getInFlightExitingAmount() external view returns (uint256 amount);

    /**
     * @notice Get the prior epoch pending amount for an operator.
     * @dev This is the amount credited toward the operator's share in selection
     * @param operator Address of the operator
     * @return amount The operator's prior epoch pending amount
     */
    function getOperatorPriorEpochPendingAmount(
        address operator
    ) external view returns (uint256 amount);

    /**
     * @notice Get the current epoch pending amount for an operator.
     * @dev This amount is NOT credited until the next epoch (anti-gaming)
     * @param operator Address of the operator
     * @return amount The operator's current epoch pending amount
     */
    function getOperatorCurrentEpochPendingAmount(
        address operator
    ) external view returns (uint256 amount);

    /**
     * @notice Get the maximum stake per validator registration.
     * @return maximum Maximum stake amount (type(uint256).max = unlimited)
     */
    function getMaximumValidatorStake() external view returns (uint256 maximum);

    /**
     * @notice Get the maximum stake per delegator registration.
     * @return maximum Maximum stake amount (type(uint256).max = unlimited)
     */
    function getMaximumDelegatorStake() external view returns (uint256 maximum);

    /**
     * @notice Get the maximum number of operators.
     * @return max Maximum operators allowed
     */
    function getMaxOperators() external view returns (uint256 max);

    /**
     * @notice Get the maximum validators per operator.
     * @return max Maximum validators per operator
     */
    function getMaxValidatorsPerOperator() external view returns (uint256 max);

    /**
     * @notice Get the flat fee deducted from each withdrawal request.
     * @return fee Withdrawal request fee (0 = no fee)
     */
    function getWithdrawalRequestFee() external view returns (uint256 fee);
}

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {PChainOwner} from "gokite-contracts/contracts/validator-manager/interfaces/IACP99Manager.sol";

/**
 * @title IStakingVaultOperations
 * @notice Interface for the StakingVaultOperations extension contract
 * @dev This contract is called via delegatecall from StakingVault
 */
interface IStakingVaultOperations {
    // ============================================
    // Events
    // ============================================

    /**
     * @notice Emitted when validator registration is initiated.
     * @param operator Address of the operator registering the validator
     * @param validationID ID of the registered validator
     */
    event StakingVault__ValidatorRegistrationInitiated(address indexed operator, bytes32 indexed validationID);

    /**
     * @notice Emitted when validator registration is completed.
     * @param validationID ID of the registered validator
     */
    event StakingVault__ValidatorRegistrationCompleted(bytes32 indexed validationID);

    /**
     * @notice Emitted when validator removal is initiated.
     * @param operator Address of the operator initiating removal
     * @param validationID ID of the validator being removed
     */
    event StakingVault__ValidatorRemovalInitiated(address indexed operator, bytes32 indexed validationID);

    /**
     * @notice Emitted when validator removal is completed.
     * @param validationID ID of the removed validator
     * @param stakeReturned Amount of stake returned
     * @param rewards Amount of rewards claimed
     */
    event StakingVault__ValidatorRemovalCompleted(bytes32 indexed validationID, uint256 stakeReturned, uint256 rewards);

    /**
     * @notice Emitted when delegator registration is initiated.
     * @param operator Address of the operator registering the delegation
     * @param validationID ID of the validator being delegated to
     * @param delegationID ID of the new delegation
     * @param amount Amount delegated
     */
    event StakingVault__DelegatorRegistrationInitiated(
        address indexed operator, bytes32 indexed validationID, bytes32 delegationID, uint256 amount
    );

    /**
     * @notice Emitted when delegator registration is completed.
     * @param operator Address of the operator
     * @param delegationID ID of the delegation
     */
    event StakingVault__DelegatorRegistrationCompleted(address indexed operator, bytes32 indexed delegationID);

    /**
     * @notice Emitted when delegator removal is initiated.
     * @param operator Address of the operator
     * @param delegationID ID of the delegation being removed
     */
    event StakingVault__DelegatorRemovalInitiated(address indexed operator, bytes32 indexed delegationID);

    /**
     * @notice Emitted when delegator removal is completed.
     * @param delegationID ID of the removed delegation
     * @param stakeReturned Amount of stake returned
     * @param rewards Amount of rewards claimed
     */
    event StakingVault__DelegatorRemovalCompleted(bytes32 indexed delegationID, uint256 stakeReturned, uint256 rewards);

    /**
     * @notice Emitted when delegator removal fails (e.g., validator already ended).
     * @param delegationID ID of the delegation
     * @param operator Address of the operator
     */
    event StakingVault__DelegatorRemovalFailed(bytes32 indexed delegationID, address indexed operator);

    /**
     * @notice Emitted when validator removal fails (e.g., staking manager rejects the call).
     * @param validationID ID of the validator
     * @param operator Address of the operator
     */
    event StakingVault__ValidatorRemovalFailed(bytes32 indexed validationID, address indexed operator);

    /**
     * @notice Emitted when rewards are harvested from validators/delegations.
     * @param totalRewards Total rewards harvested
     * @param protocolFee Protocol fee taken
     * @param poolIncrease Amount added to pool
     */
    event StakingVault__Harvested(uint256 totalRewards, uint256 protocolFee, uint256 poolIncrease);

    /**
     * @notice Emitted when a new operator is added.
     * @param operator Address of the new operator
     * @param allocationBips Allocation percentage in basis points
     */
    event StakingVault__OperatorAdded(address indexed operator, uint256 allocationBips);

    /**
     * @notice Emitted when an operator is removed.
     * @param operator Address of the removed operator
     */
    event StakingVault__OperatorRemoved(address indexed operator);

    /**
     * @notice Emitted when an operator's allocation is updated.
     * @param operator Address of the operator
     * @param oldBips Previous allocation in basis points
     * @param newBips New allocation in basis points
     */
    event StakingVault__OperatorAllocationUpdated(address indexed operator, uint256 oldBips, uint256 newBips);

    /**
     * @notice Emitted when an operator claims their accrued fees.
     * @param operator Address of the operator
     * @param amount Amount of fees claimed
     */
    event StakingVault__OperatorFeesClaimed(address indexed operator, uint256 amount);

    /**
     * @notice Emitted when an operator's fee recipient is updated.
     * @param operator Address of the operator
     * @param oldRecipient Previous fee recipient
     * @param newRecipient New fee recipient
     */
    event StakingVault__OperatorFeeRecipientUpdated(
        address indexed operator, address indexed oldRecipient, address indexed newRecipient
    );

    /**
     * @notice Emitted when liquidity is prepared for withdrawals.
     * @param epoch Current epoch number
     * @param removalsInitiated Number of delegation/validator removals initiated
     * @param amountExpected Expected amount to be freed
     */
    event StakingVault__LiquidityPrepared(uint256 indexed epoch, uint256 removalsInitiated, uint256 amountExpected);

    /**
     * @notice Emitted when the in-flight exiting amount is updated.
     * @param newAmount New in-flight exiting amount
     */
    event StakingVault__InFlightExitingUpdated(uint256 newAmount);

    /**
     * @notice Emitted when exit debt is recorded for an operator.
     * @param operator Address of the operator
     * @param debtAmount Amount of debt added
     * @param totalDebt New total debt for the operator
     */
    event StakingVault__ExitDebtRecorded(address indexed operator, uint256 debtAmount, uint256 totalDebt);

    /**
     * @notice Emitted when exit debt is reduced for an operator.
     * @param operator Address of the operator
     * @param reducedAmount Amount of debt reduced
     * @param remainingDebt Remaining debt for the operator
     */
    event StakingVault__ExitDebtReduced(address indexed operator, uint256 reducedAmount, uint256 remainingDebt);

    /**
     * @notice Emitted when an accounting mismatch is detected (informational).
     * @param context Description of where the mismatch occurred
     * @param expected Expected value
     * @param actual Actual value found
     */
    event StakingVault__AccountingMismatchDetected(string context, uint256 expected, uint256 actual);

    /**
     * @notice Emitted when an externally-initiated PendingRemoved delegation is adopted by the vault.
     * @param operator Address of the operator
     * @param delegationID ID of the delegation
     * @param amount Delegation principal amount
     */
    event StakingVault__DelegatorRemovalAdopted(address indexed operator, bytes32 indexed delegationID, uint256 amount);

    /**
     * @notice Emitted when protocol fees are escrowed because the recipient reverted.
     * @param amount Amount of fees escrowed in this call
     * @param totalPending New total pending protocol fees
     */
    event StakingVault__ProtocolFeeEscrowed(uint256 amount, uint256 totalPending);

    /**
     * @notice Emitted when operator fees are forfeited to the pool because the recipient reverted.
     * @param operator Address of the operator whose fees were forfeited
     * @param amount Amount of fees forfeited
     */
    event StakingVault__OperatorFeesForfeited(address indexed operator, uint256 amount);

    /**
     * @notice Emitted when a delegator registration is aborted (e.g., target validator removed).
     * @param delegationID ID of the aborted delegation
     * @param amount Principal amount refunded
     */
    event StakingVault__DelegatorRegistrationAborted(bytes32 indexed delegationID, uint256 amount);

    // ============================================
    // Validator Lifecycle
    // ============================================

    /**
     * @notice Initiate registration of a new validator (operator only).
     * @dev Uses the vault's operatorFeeBips as the validator's delegation fee.
     * @param nodeID Node ID of the validator
     * @param blsPublicKey BLS public key for the validator
     * @param remainingBalanceOwner P-Chain owner for remaining balance
     * @param disableOwner P-Chain owner for disable operations
     * @param amount Amount of pool stake for the validator
     * @return validationID ID of the registered validator
     */
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint256 amount
    ) external returns (bytes32 validationID);

    /**
     * @notice Complete validator registration after P-Chain confirmation.
     * @param messageIndex Index of the P-Chain message
     * @return validationID ID of the registered validator
     */
    function completeValidatorRegistration(
        uint32 messageIndex
    ) external returns (bytes32 validationID);

    /**
     * @notice Initiate validator removal (operator only, for own validators).
     * @param validationID ID of the validator to remove
     */
    function initiateValidatorRemoval(
        bytes32 validationID
    ) external;

    /**
     * @notice Complete validator removal after P-Chain confirmation.
     * @param messageIndex Index of the P-Chain message
     * @return validationID ID of the removed validator
     */
    function completeValidatorRemoval(
        uint32 messageIndex
    ) external returns (bytes32 validationID);

    /**
     * @notice Emergency remove validator (admin only).
     * @param validationID ID of the validator to force remove
     */
    function forceRemoveValidator(
        bytes32 validationID
    ) external;

    // ============================================
    // Delegator Lifecycle
    // ============================================

    /**
     * @notice Initiate registration of a new delegator to any validator (operator only).
     * @param validationID ID of the validator to delegate to
     * @param amount Amount to delegate
     * @return delegationID ID of the new delegation
     */
    function initiateDelegatorRegistration(
        bytes32 validationID,
        uint256 amount
    ) external returns (bytes32 delegationID);

    /**
     * @notice Complete delegation registration after P-Chain confirmation.
     * @param delegationID ID of the delegation
     * @param messageIndex Index of the P-Chain weight update message
     * @param uptimeMessageIndex Index of the uptime proof message
     */
    function completeDelegatorRegistration(
        bytes32 delegationID,
        uint32 messageIndex,
        uint32 uptimeMessageIndex
    ) external;

    /**
     * @notice Initiate removal of any delegator (operator who created it, or owner).
     * @param delegationID ID of the delegation to remove
     */
    function initiateDelegatorRemoval(
        bytes32 delegationID
    ) external;

    /**
     * @notice Complete delegator removal after P-Chain confirmation.
     * @param delegationID ID of the delegation
     * @param messageIndex Index of the P-Chain message
     */
    function completeDelegatorRemoval(
        bytes32 delegationID,
        uint32 messageIndex
    ) external;

    /**
     * @notice Emergency remove delegator (admin only).
     * @param delegationID ID of the delegation to force remove
     */
    function forceRemoveDelegator(
        bytes32 delegationID
    ) external;

    // ============================================
    // Liquidity Management
    // ============================================

    /**
     * @notice Prepare withdrawals by initiating delegation removals to free liquidity.
     * @dev Only considers requests from previous epochs (requestEpoch < currentEpoch).
     *      This prevents front-running by requiring requests to age at least one epoch
     *      before triggering delegation/validator removals.
     */
    function prepareWithdrawals() external;

    // ============================================
    // Harvesting
    // ============================================

    /**
     * @notice Harvest rewards from all validators/delegations.
     * @dev Gas warning: iterates over all operators and all their validators/delegations in a single
     *      call. At scale, use `harvestValidators` and `harvestDelegators` with batch parameters instead.
     * @return totalRewards Total rewards harvested
     */
    function harvest() external returns (uint256 totalRewards);

    /**
     * @notice Harvest validator rewards for a single operator with batching.
     * @param operatorIndex Index of the operator in the operator list
     * @param start Starting index in the operator's validator list
     * @param batchSize Maximum number of validators to harvest
     * @return totalRewards Total rewards harvested
     */
    function harvestValidators(
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) external returns (uint256 totalRewards);

    /**
     * @notice Harvest delegation rewards for a single operator with batching.
     * @param operatorIndex Index of the operator in the operator list
     * @param start Starting index in the operator's delegation list
     * @param batchSize Maximum number of delegations to harvest
     * @return totalRewards Total rewards harvested
     */
    function harvestDelegators(
        uint256 operatorIndex,
        uint256 start,
        uint256 batchSize
    ) external returns (uint256 totalRewards);

    // ============================================
    // Operator Management
    // ============================================

    /**
     * @notice Add a new operator.
     * @param operator Address of the operator to add
     * @param allocationBips Allocation percentage in basis points
     * @param feeRecipient Address to receive operator fees (use operator address if same)
     */
    function addOperator(
        address operator,
        uint256 allocationBips,
        address feeRecipient
    ) external;

    /**
     * @notice Remove an operator (must have no active validators).
     * @param operator Address of the operator to remove
     */
    function removeOperator(
        address operator
    ) external;

    /**
     * @notice Update operator allocations in batch.
     * @param operators Addresses of the operators to update
     * @param newBips New allocations in basis points
     */
    function updateOperatorAllocations(
        address[] calldata operators,
        uint256[] calldata newBips
    ) external;

    /**
     * @notice Claim accrued operator fees.
     */
    function claimOperatorFees() external;

    /**
     * @notice Force-claim an operator's accrued fees (operator manager only).
     * @dev Sends fees to the operator's configured feeRecipient.
     *      Intended to unblock removeOperator when an operator refuses to claim.
     * @param operator Address of the operator whose fees to claim
     */
    function forceClaimOperatorFees(
        address operator
    ) external;

    /**
     * @notice Set the fee recipient address for the calling operator.
     * @param feeRecipient New fee recipient address (address(0) to use operator address)
     */
    function setOperatorFeeRecipient(
        address feeRecipient
    ) external;
}

