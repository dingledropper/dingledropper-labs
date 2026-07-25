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

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

/**
 * @notice Interface for Validation and Delegation reward calculators
 */
