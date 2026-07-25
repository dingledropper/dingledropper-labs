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

