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
