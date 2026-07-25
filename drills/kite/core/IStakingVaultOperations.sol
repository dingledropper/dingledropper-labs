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

