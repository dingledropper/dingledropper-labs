contract StakingVault is
    Initializable,
    ERC20Upgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    IStakingVault,
    IStakingVaultOperations
{
    using StakingVaultStorageLib for *;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ============================================
    // Role Constants
    // ============================================

    /// @notice Role constant exposed for external access (actual value in StakingVaultStorageLib)
    bytes32 public constant OPERATOR_MANAGER_ROLE = StakingVaultStorageLib.OPERATOR_MANAGER_ROLE;

    /// @notice Role constant for vault administration (fees, pause, force-removal)
    bytes32 public constant VAULT_ADMIN_ROLE = StakingVaultStorageLib.VAULT_ADMIN_ROLE;

    // ============================================
    // Reentrancy Guard Modifier
    // ============================================

    modifier nonReentrant() {
        StakingVaultStorageLib._nonReentrantBefore();
        _;
        StakingVaultStorageLib._nonReentrantAfter();
    }

    // ============================================
    // Constructor (disable initializers)
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============================================
    // Initializer
    // ============================================

    /// @inheritdoc IStakingVault
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
    ) external initializer {
        StakingVaultInternals.requireNonZero(_stakingManager);
        StakingVaultInternals.requireNonZero(_protocolFeeRecipient);
        StakingVaultInternals.requireNonZero(_operatorManager);
        StakingVaultInternals.requireNonZero(_defaultAdmin);
        StakingVaultInternals.requireNonZero(_vaultAdmin);
        StakingVaultInternals.requireNonZero(_operationsImpl);
        _validateOperationsImpl(_operationsImpl);
        if (_protocolFeeBips > StakingVaultStorageLib.MAX_PROTOCOL_FEE_BIPS) {
            revert StakingVault__InvalidFee(_protocolFeeBips);
        }
        if (_epochDuration == 0) revert StakingVault__InvalidEpochDuration();
        if (_liquidityBufferBips > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert StakingVault__InvalidFee(_liquidityBufferBips);
        }

        __ERC20_init(_name, _symbol);
        __AccessControlDefaultAdminRules_init(_defaultAdminDelay, _defaultAdmin);
        StakingVaultStorageLib.__ReentrancyGuard_init();
        __Pausable_init();

        // Grant non-DEFAULT_ADMIN roles (DEFAULT_ADMIN is handled by __AccessControlDefaultAdminRules_init)
        _grantRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE, _vaultAdmin);
        _grantRole(StakingVaultStorageLib.OPERATOR_MANAGER_ROLE, _operatorManager);

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        $.stakingManager = IKiteStakingManager(_stakingManager);
        $.protocolFeeRecipient = _protocolFeeRecipient;
        $.protocolFeeBips = _protocolFeeBips;
        $.epochDuration = _epochDuration;
        $.epochStartTime = block.timestamp;
        $.liquidityBufferBips = _liquidityBufferBips;
        $.operationsImpl = _operationsImpl;
        $.maximumValidatorStake = type(uint256).max;
        $.maximumDelegatorStake = type(uint256).max;
        $.maxOperators = StakingVaultStorageLib.DEFAULT_MAX_OPERATORS;
        $.maxValidatorsPerOperator = StakingVaultStorageLib.DEFAULT_MAX_VALIDATORS_PER_OPERATOR;

        // Cache immutable values from StakingManager (these never change after init)
        _cacheStakingManagerSettings();
    }

    // ============================================
    // Receive & Fallback
    // ============================================

    /// @notice Receive native token (for staking manager returns, rewards, etc.)
    receive() external payable {
        if (!StakingVaultStorageLib._getStorage().isReceivingManagerFunds) {
            revert IStakingVault.StakingVault__UnauthorizedReceive();
        }
    }

    /**
     * @notice Forward unknown function calls to operationsImpl via delegatecall
     * @dev Standard pattern for contract splitting (similar to EIP-2535 Diamond)
     */
    fallback() external payable {
        _delegateToOperations();
    }

    // ============================================
    // Operations Forwarding Stubs
    // ============================================

    /// @inheritdoc IStakingVaultOperations
    function initiateValidatorRegistration(
        bytes memory,
        bytes memory,
        PChainOwner memory,
        PChainOwner memory,
        uint256
    ) external returns (bytes32 validationID) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function completeValidatorRegistration(
        uint32
    ) external returns (bytes32 validationID) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function initiateValidatorRemoval(
        bytes32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function completeValidatorRemoval(
        uint32
    ) external returns (bytes32 validationID) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function forceRemoveValidator(
        bytes32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function initiateDelegatorRegistration(
        bytes32,
        uint256
    ) external returns (bytes32 delegationID) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function completeDelegatorRegistration(
        bytes32,
        uint32,
        uint32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function initiateDelegatorRemoval(
        bytes32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function completeDelegatorRemoval(
        bytes32,
        uint32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function forceRemoveDelegator(
        bytes32
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function prepareWithdrawals() external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function harvest() external returns (uint256 totalRewards) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function harvestValidators(
        uint256,
        uint256,
        uint256
    ) external returns (uint256 totalRewards) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function harvestDelegators(
        uint256,
        uint256,
        uint256
    ) external returns (uint256 totalRewards) {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function addOperator(
        address,
        uint256,
        address
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function removeOperator(
        address
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function updateOperatorAllocations(
        address[] calldata,
        uint256[] calldata
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function claimOperatorFees() external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function forceClaimOperatorFees(
        address
    ) external {
        _delegateToOperations();
    }

    /// @inheritdoc IStakingVaultOperations
    function setOperatorFeeRecipient(
        address
    ) external {
        _delegateToOperations();
    }

    // ============================================
    // Operations Implementation Management
    // ============================================

    /// @inheritdoc IStakingVault
    function setOperationsImpl(
        address _operationsImpl
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        StakingVaultInternals.requireNonZero(_operationsImpl);
        _validateOperationsImpl(_operationsImpl);
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        address oldImpl = $.operationsImpl;
        $.operationsImpl = _operationsImpl;
        emit IStakingVault.StakingVault__OperationsImplUpdated(oldImpl, _operationsImpl);
    }

    /// @inheritdoc IStakingVault
    function getOperationsImpl() external view returns (address impl) {
        return StakingVaultStorageLib._getStorage().operationsImpl;
    }

    // ============================================
    // User Functions
    // ============================================

    /**
     * @inheritdoc IStakingVault
     * @dev Reverts during insolvency (totalSupply() > 0 && getTotalPooledStake() == 0) to protect existing depositors.
     *      This prevents dilution of existing shares when the vault has negative equity.
     */
    function deposit(
        uint256 minShares
    ) external payable nonReentrant whenNotPaused returns (uint256 shares) {
        if (msg.value == 0) revert StakingVault__InvalidAmount();

        uint256 preDepositStake = getTotalPooledStake();
        if (totalSupply() > 0 && preDepositStake == 0) revert StakingVault__Insolvent();
        shares = _stakeToShares(msg.value, preDepositStake);
        if (shares == 0) revert StakingVault__InvalidAmount();

        if (minShares > 0 && shares < minShares) {
            revert StakingVault__SlippageExceeded(shares, minShares);
        }

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        $.vaultAccountedBalance += msg.value;
        _mint(msg.sender, shares);

        emit IStakingVault.StakingVault__Deposited(msg.sender, msg.value, shares);
    }

    /// @inheritdoc IStakingVault
    function requestWithdrawal(
        uint256 shares
    ) external nonReentrant whenNotPaused returns (uint256 requestId) {
        if (shares == 0) revert StakingVault__InvalidAmount();
        uint256 balance = balanceOf(msg.sender);
        if (balance < shares) {
            revert StakingVault__InsufficientBalance(shares, balance);
        }

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 stakeAmount = _sharesToStake(shares);

        uint256 fee = $.withdrawalRequestFee;
        if (fee > 0) {
            if (stakeAmount <= fee) revert StakingVault__InvalidAmount();
            stakeAmount -= fee;
            $.vaultAccountedBalance -= fee;
            (bool feeSuccess,) = $.protocolFeeRecipient.call{value: fee}("");
            if (!feeSuccess) {
                $.vaultAccountedBalance += fee;
                $.pendingProtocolFees += fee;
                emit IStakingVaultOperations.StakingVault__ProtocolFeeEscrowed(fee, $.pendingProtocolFees);
            }
        }

        _burn(msg.sender, shares);

        uint256 currentEpoch = getCurrentEpoch();

        requestId = $.withdrawalQueue.length;
        $.withdrawalQueue
            .push(
                WithdrawalRequest({
                    user: msg.sender,
                    shares: shares,
                    stakeAmount: stakeAmount,
                    requestEpoch: currentEpoch,
                    fulfilled: false
                })
            );

        $.pendingWithdrawalStake += stakeAmount;

        uint256 epoch = currentEpoch;
        if ($.currentEpochWithdrawalEpoch != epoch) {
            $.currentEpochWithdrawalEpoch = epoch;
            $.currentEpochWithdrawalAmount = stakeAmount;
        } else {
            $.currentEpochWithdrawalAmount += stakeAmount;
        }

        emit IStakingVault.StakingVault__WithdrawalRequested(msg.sender, requestId, shares, stakeAmount);
    }

    /// @inheritdoc IStakingVault
    function claimWithdrawal(
        uint256 requestId
    ) external nonReentrant {
        (address user, uint256 stakeAmount) = _claimWithdrawalInternal(requestId, true);
        _sendWithdrawalOrEscrow(user, requestId, stakeAmount);
    }

    /// @inheritdoc IStakingVault
    function claimWithdrawalFor(
        uint256 requestId
    ) external nonReentrant {
        (address user, uint256 stakeAmount) = _claimWithdrawalInternal(requestId, false);
        _sendWithdrawalOrEscrow(user, requestId, stakeAmount);
    }

    /// @inheritdoc IStakingVault
    function claimWithdrawals(
        uint256[] calldata requestIds
    ) external nonReentrant {
        for (uint256 i; i < requestIds.length;) {
            (address user, uint256 stakeAmount) = _claimWithdrawalInternal(requestIds[i], true);
            _sendWithdrawalOrEscrow(user, requestIds[i], stakeAmount);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IStakingVault
    function claimWithdrawalsFor(
        uint256[] calldata requestIds
    ) external nonReentrant {
        for (uint256 i; i < requestIds.length;) {
            (address user, uint256 stakeAmount) = _claimWithdrawalInternal(requestIds[i], false);
            _sendWithdrawalOrEscrow(user, requestIds[i], stakeAmount);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IStakingVault
    function claimEscrowedWithdrawal(
        address recipient
    ) external nonReentrant {
        StakingVaultInternals.requireNonZero(recipient);
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 amount = $.withdrawalEscrow[msg.sender];
        if (amount == 0) revert StakingVault__NoEscrowedWithdrawal();
        $.withdrawalEscrow[msg.sender] = 0;
        $.totalEscrowedWithdrawals -= amount;
        $.vaultAccountedBalance -= amount;
        StakingVaultInternals.sendValue(payable(recipient), amount);
        emit IStakingVault.StakingVault__EscrowedWithdrawalClaimed(msg.sender, recipient, amount);
    }

    // ============================================
    // Epoch Processing
    // ============================================

    /// @inheritdoc IStakingVault
    function processEpoch() external nonReentrant returns (bool finished) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 currentEpoch = getCurrentEpoch();
        if (currentEpoch <= $.lastEpochProcessed) {
            revert StakingVault__EpochNotEnded();
        }

        uint256 availableBalance = StakingVaultInternals.getAvailableStake();

        uint256 withdrawalsFulfilled = 0;
        uint256 stakeReleased = 0;
        uint256 claimableDelta = 0;

        uint256 startIdx = $.queueProcessHead > $.queueHead ? $.queueProcessHead : $.queueHead;
        uint256 i = startIdx;
        uint256 queueLen = $.withdrawalQueue.length;
        uint256 scanned;
        bool scanCapHit;
        while (i < queueLen) {
            if (scanned >= StakingVaultStorageLib.MAX_PROCESS_PER_CALL || gasleft() <= 120_000) {
                scanCapHit = true;
                break;
            }

            WithdrawalRequest storage request = $.withdrawalQueue[i];

            if (request.requestEpoch >= currentEpoch) break;

            if (request.fulfilled || $.withdrawalClaimable[i]) {
                unchecked {
                    ++i;
                    ++scanned;
                }
                continue;
            }

            uint256 stakeAmount = request.stakeAmount;
            if (stakeAmount > availableBalance) {
                scanCapHit = true;
                break;
            }

            $.withdrawalClaimable[i] = true;
            claimableDelta += stakeAmount;
            availableBalance -= stakeAmount;
            stakeReleased += stakeAmount;
            unchecked {
                ++withdrawalsFulfilled;
                ++i;
                ++scanned;
            }
        }

        if (claimableDelta > 0) {
            $.claimableWithdrawalStake += claimableDelta;
        }

        $.queueProcessHead = i;

        _advanceQueueHead($);

        finished = !scanCapHit;
        if (finished) {
            $.lastEpochProcessed = currentEpoch;
        }

        uint256 requestsRemaining = $.withdrawalQueue.length - $.queueHead;
        emit IStakingVault.StakingVault__EpochProcessed(
            currentEpoch, withdrawalsFulfilled, stakeReleased, requestsRemaining
        );
    }

    // ============================================
    // Admin Configuration
    // ============================================

    /// @inheritdoc IStakingVault
    function setProtocolFeeBips(
        uint256 bips
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (bips > StakingVaultStorageLib.MAX_PROTOCOL_FEE_BIPS) {
            revert StakingVault__InvalidFee(bips);
        }

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (bips + $.operatorFeeBips > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert StakingVault__InvalidFee(bips);
        }

        uint256 oldFee = $.protocolFeeBips;
        $.protocolFeeBips = bips;

        emit IStakingVault.StakingVault__ProtocolFeeUpdated(oldFee, bips);
    }

    /// @inheritdoc IStakingVault
    function setProtocolFeeRecipient(
        address _protocolFeeRecipient
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        StakingVaultInternals.requireNonZero(_protocolFeeRecipient);

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        address oldRecipient = $.protocolFeeRecipient;
        $.protocolFeeRecipient = _protocolFeeRecipient;
        emit IStakingVault.StakingVault__ProtocolFeeRecipientUpdated(oldRecipient, _protocolFeeRecipient);
    }

    /// @inheritdoc IStakingVault
    function setLiquidityBufferBips(
        uint256 _liquidityBufferBips
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (_liquidityBufferBips > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert StakingVault__InvalidFee(_liquidityBufferBips);
        }

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        uint256 oldBips = $.liquidityBufferBips;
        $.liquidityBufferBips = _liquidityBufferBips;
        emit IStakingVault.StakingVault__LiquidityBufferUpdated(oldBips, _liquidityBufferBips);
    }

    /// @inheritdoc IStakingVault
    function setOperatorFeeBips(
        uint256 bips
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (bips > StakingVaultStorageLib.MAX_OPERATOR_FEE_BIPS) {
            revert StakingVault__InvalidFee(bips);
        }
        uint16 minFeeBips = _getMinimumDelegationFeeBips();
        if (bips < uint256(minFeeBips)) {
            revert StakingVault__InvalidFee(bips);
        }

        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (bips + $.protocolFeeBips > StakingVaultStorageLib.BIPS_DENOMINATOR) {
            revert StakingVault__InvalidFee(bips);
        }

        uint256 oldFee = $.operatorFeeBips;
        $.operatorFeeBips = bips;

        emit IStakingVault.StakingVault__OperatorFeeUpdated(oldFee, bips);
    }

    /// @inheritdoc IStakingVault
    function setMaximumValidatorStake(
        uint256 amount
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 oldMax = $.maximumValidatorStake;
        $.maximumValidatorStake = amount;
        emit IStakingVault.StakingVault__MaximumValidatorStakeUpdated(oldMax, amount);
    }

    /// @inheritdoc IStakingVault
    function setMaximumDelegatorStake(
        uint256 amount
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 oldMax = $.maximumDelegatorStake;
        $.maximumDelegatorStake = amount;
        emit IStakingVault.StakingVault__MaximumDelegatorStakeUpdated(oldMax, amount);
    }

    /// @inheritdoc IStakingVault
    function setMaxOperators(
        uint256 newMax
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (newMax == 0) revert StakingVault__InvalidAmount();
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 oldMax = $.maxOperators;
        $.maxOperators = newMax;
        emit IStakingVault.StakingVault__MaxOperatorsUpdated(oldMax, newMax);
    }

    /// @inheritdoc IStakingVault
    function setMaxValidatorsPerOperator(
        uint256 newMax
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (newMax == 0) revert StakingVault__InvalidAmount();
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 oldMax = $.maxValidatorsPerOperator;
        $.maxValidatorsPerOperator = newMax;
        emit IStakingVault.StakingVault__MaxValidatorsPerOperatorUpdated(oldMax, newMax);
    }

    /// @inheritdoc IStakingVault
    function setWithdrawalRequestFee(
        uint256 fee
    ) external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        if (fee > StakingVaultStorageLib.MAX_WITHDRAWAL_REQUEST_FEE) revert StakingVault__InvalidFee(fee);
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 oldFee = $.withdrawalRequestFee;
        $.withdrawalRequestFee = fee;
        emit IStakingVault.StakingVault__WithdrawalRequestFeeUpdated(oldFee, fee);
    }

    /// @inheritdoc IStakingVault
    function claimPendingProtocolFees() external nonReentrant onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 amount = $.pendingProtocolFees;
        if (amount == 0) revert StakingVault__NoFeesToClaim();
        $.pendingProtocolFees = 0;
        $.vaultAccountedBalance -= amount;
        StakingVaultInternals.sendValue(payable($.protocolFeeRecipient), amount);
        emit IStakingVault.StakingVault__PendingProtocolFeesClaimed(amount);
    }

    // ============================================
    // Emergency Functions
    // ============================================

    /// @inheritdoc IStakingVault
    function pause() external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @inheritdoc IStakingVault
    function unpause() external onlyRole(StakingVaultStorageLib.VAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // View Functions
    // ============================================

    /// @inheritdoc IStakingVault
    function getExchangeRate() external view returns (uint256 rate) {
        return _getExchangeRate();
    }

    /// @inheritdoc IStakingVault
    function getTotalPooledStake() public view returns (uint256 stake) {
        return StakingVaultInternals.getTotalPooledStake();
    }

    /// @inheritdoc IStakingVault
    function getAvailableStake() public view returns (uint256 stake) {
        return StakingVaultInternals.getAvailableStake();
    }

    /// @inheritdoc IStakingVault
    function getPendingProtocolFees() external view returns (uint256 fees) {
        return StakingVaultStorageLib._getStorage().pendingProtocolFees;
    }

    /// @inheritdoc IStakingVault
    function getPendingWithdrawals() external view returns (uint256 amount) {
        return StakingVaultStorageLib._getStorage().pendingWithdrawalStake;
    }

    /// @inheritdoc IStakingVault
    function getClaimableWithdrawalStake() external view returns (uint256 stake) {
        return StakingVaultStorageLib._getStorage().claimableWithdrawalStake;
    }

    /// @inheritdoc IStakingVault
    function isWithdrawalClaimable(
        uint256 requestId
    ) external view returns (bool claimable) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (requestId >= $.withdrawalQueue.length) {
            return false;
        }
        return $.withdrawalClaimable[requestId];
    }

    /// @inheritdoc IStakingVault
    function pendingRedeemRequest(
        address owner_
    ) external view returns (uint256) {
        return _getRedeemRequestAmount(owner_, false);
    }

    /// @inheritdoc IStakingVault
    function claimableRedeemRequest(
        address owner_
    ) external view returns (uint256) {
        return _getRedeemRequestAmount(owner_, true);
    }

    function _getRedeemRequestAmount(
        address owner_,
        bool isClaimable
    ) internal view returns (uint256 amount) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        for (uint256 i = $.queueHead; i < $.withdrawalQueue.length; i++) {
            if (
                $.withdrawalQueue[i].user == owner_ && !$.withdrawalQueue[i].fulfilled
                    && $.withdrawalClaimable[i] == isClaimable
            ) {
                amount += $.withdrawalQueue[i].stakeAmount;
            }
        }
    }

    /// @inheritdoc IStakingVault
    function getCurrentEpoch() public view returns (uint256 epoch) {
        return StakingVaultInternals.getCurrentEpoch();
    }

    /// @inheritdoc IStakingVault
    function getEpochDuration() external view returns (uint256 duration) {
        return StakingVaultStorageLib._getStorage().epochDuration;
    }

    /// @inheritdoc IStakingVault
    function getStartTime() external view returns (uint256 startTime) {
        return StakingVaultStorageLib._getStorage().epochStartTime;
    }

    /// @inheritdoc IStakingVault
    function getOperatorInfo(
        address operator
    ) external view returns (Operator memory info) {
        return StakingVaultStorageLib._getStorage().operators[operator];
    }

    /// @inheritdoc IStakingVault
    function getWithdrawalRequest(
        uint256 requestId
    ) external view returns (WithdrawalRequest memory request) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        if (requestId >= $.withdrawalQueue.length) {
            revert StakingVault__WithdrawalNotFound(requestId);
        }
        WithdrawalRequest memory req = $.withdrawalQueue[requestId];
        if (req.user == address(0)) {
            revert StakingVault__WithdrawalNotFound(requestId);
        }
        return req;
    }

    /// @inheritdoc IStakingVault
    function getStakingManager() external view returns (address manager) {
        return address(StakingVaultStorageLib._getStorage().stakingManager);
    }

    /// @inheritdoc IStakingVault
    function getProtocolFeeRecipient() external view returns (address recipient) {
        return StakingVaultStorageLib._getStorage().protocolFeeRecipient;
    }

    /// @inheritdoc IStakingVault
    function getProtocolFeeBips() external view returns (uint256 bips) {
        return StakingVaultStorageLib._getStorage().protocolFeeBips;
    }

    /// @inheritdoc IStakingVault
    function getLiquidityBufferBips() external view returns (uint256 bips) {
        return StakingVaultStorageLib._getStorage().liquidityBufferBips;
    }

    /// @inheritdoc IStakingVault
    function getOperatorFeeBips() external view returns (uint256 bips) {
        return StakingVaultStorageLib._getStorage().operatorFeeBips;
    }

    /// @inheritdoc IStakingVault
    function getTotalDelegatedStake() external view returns (uint256 stake) {
        return StakingVaultStorageLib._getStorage().totalDelegatedStake;
    }

    /// @inheritdoc IStakingVault
    function getOperatorList() external view returns (address[] memory operators) {
        return StakingVaultStorageLib._getStorage().operatorSet.values();
    }

    /// @inheritdoc IStakingVault
    function getQueueHead() external view returns (uint256 index) {
        return StakingVaultStorageLib._getStorage().queueHead;
    }

    /// @inheritdoc IStakingVault
    function getWithdrawalQueueLength() external view returns (uint256 length) {
        return StakingVaultStorageLib._getStorage().withdrawalQueue.length;
    }

    /// @inheritdoc IStakingVault
    function getWithdrawalRequestIds(
        address user
    ) external view returns (uint256[] memory requestIds) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        uint256 count;
        for (uint256 i = $.queueHead; i < $.withdrawalQueue.length; i++) {
            if ($.withdrawalQueue[i].user == user && !$.withdrawalQueue[i].fulfilled) {
                count++;
            }
        }
        requestIds = new uint256[](count);
        uint256 idx;
        for (uint256 i = $.queueHead; i < $.withdrawalQueue.length; i++) {
            if ($.withdrawalQueue[i].user == user && !$.withdrawalQueue[i].fulfilled) {
                requestIds[idx++] = i;
            }
        }
    }

    /// @inheritdoc IStakingVault
    function getLastEpochProcessed() external view returns (uint256 epoch) {
        return StakingVaultStorageLib._getStorage().lastEpochProcessed;
    }

    /// @inheritdoc IStakingVault
    function isValidatorPendingRemoval(
        bytes32 validationID
    ) external view returns (bool pending) {
        return StakingVaultStorageLib._getStorage().validatorPendingRemoval[validationID];
    }

    /// @inheritdoc IStakingVault
    function getMinimumStakeDuration() external view returns (uint64 duration) {
        return StakingVaultInternals.getMinimumStakeDuration();
    }

    /// @inheritdoc IStakingVault
    function getTotalAccruedOperatorFees() external view returns (uint256 fees) {
        return StakingVaultStorageLib._getStorage().totalAccruedOperatorFees;
    }

    /// @inheritdoc IStakingVault
    function getTotalValidatorStake() external view returns (uint256 stake) {
        return StakingVaultStorageLib._getStorage().totalValidatorStake;
    }

    /// @inheritdoc IStakingVault
    function getValidatorStakeAmount(
        bytes32 validationID
    ) external view returns (uint256 amount) {
        if (StakingVaultStorageLib._getStorage().validatorToOperator[validationID] == address(0)) {
            return 0;
        }
        return StakingVaultInternals.getValidatorStakeAmountFromManager(validationID);
    }

    /// @inheritdoc IStakingVault
    function getOperatorDelegators(
        address operatorAddr
    ) external view returns (bytes32[] memory delegationIDs) {
        return StakingVaultStorageLib._getStorage().operatorDelegations[operatorAddr].values();
    }

    /// @inheritdoc IStakingVault
    function getOperatorValidators(
        address operatorAddr
    ) external view returns (bytes32[] memory validatorIDs) {
        return StakingVaultStorageLib._getStorage().operatorValidators[operatorAddr].values();
    }

    /// @inheritdoc IStakingVault
    function getDelegatorInfo(
        bytes32 delegationID
    ) external view returns (DelegatorInfo memory info) {
        return StakingVaultStorageLib._getStorage().delegatorInfo[delegationID];
    }

    /// @inheritdoc IStakingVault
    function getOperatorExitDebt(
        address operator
    ) external view returns (uint256 debt) {
        return StakingVaultStorageLib._getStorage().operatorExitDebt[operator];
    }

    /// @inheritdoc IStakingVault
    function getTotalExitDebt() external view returns (uint256 debt) {
        return StakingVaultStorageLib._getStorage().totalExitDebt;
    }

    /// @inheritdoc IStakingVault
    function getInFlightExitingAmount() external view returns (uint256 amount) {
        return StakingVaultStorageLib._getStorage().inFlightExitingAmount;
    }

    /// @inheritdoc IStakingVault
    function getOperatorPriorEpochPendingAmount(
        address operator
    ) external view returns (uint256 amount) {
        return StakingVaultStorageLib._getStorage().operatorPriorEpochPendingAmount[operator];
    }

    /// @inheritdoc IStakingVault
    function getOperatorCurrentEpochPendingAmount(
        address operator
    ) external view returns (uint256 amount) {
        return StakingVaultStorageLib._getStorage().operatorCurrentEpochPendingAmount[operator];
    }

    /// @inheritdoc IStakingVault
    function getMaximumValidatorStake() external view returns (uint256 maximum) {
        return StakingVaultStorageLib._getStorage().maximumValidatorStake;
    }

    /// @inheritdoc IStakingVault
    function getMaximumDelegatorStake() external view returns (uint256 maximum) {
        return StakingVaultStorageLib._getStorage().maximumDelegatorStake;
    }

    /// @inheritdoc IStakingVault
    function getMaxOperators() external view returns (uint256 max) {
        return StakingVaultStorageLib._getStorage().maxOperators;
    }

    /// @inheritdoc IStakingVault
    function getMaxValidatorsPerOperator() external view returns (uint256 max) {
        return StakingVaultStorageLib._getStorage().maxValidatorsPerOperator;
    }

    /// @inheritdoc IStakingVault
    function getWithdrawalRequestFee() external view returns (uint256 fee) {
        return StakingVaultStorageLib._getStorage().withdrawalRequestFee;
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Delegatecall to operationsImpl and bubble return data via assembly return
     * @dev The assembly `return` bypasses Solidity's return handling, so callers
     *      don't need to wire up return values — the Solidity return types are ABI-only.
     */
    function _delegateToOperations() internal {
        address impl = StakingVaultStorageLib._getStorage().operationsImpl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /**
     * @notice Try to send withdrawal native token; escrow on failure
     * @param user The withdrawal recipient
     * @param requestId The withdrawal request ID (for event)
     * @param stakeAmount The amount to send
     */
    function _sendWithdrawalOrEscrow(
        address user,
        uint256 requestId,
        uint256 stakeAmount
    ) internal {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        $.vaultAccountedBalance -= stakeAmount;

        (bool success,) = payable(user).call{value: stakeAmount}("");
        if (success) {
            emit IStakingVault.StakingVault__WithdrawalClaimed(user, requestId, stakeAmount);
        } else {
            $.vaultAccountedBalance += stakeAmount;
            $.withdrawalEscrow[user] += stakeAmount;
            $.totalEscrowedWithdrawals += stakeAmount;
            emit IStakingVault.StakingVault__WithdrawalEscrowed(user, requestId, stakeAmount);
        }
    }

    /**
     * @notice Shared claim logic for claimWithdrawal and claimWithdrawalFor
     * @param requestId The withdrawal request ID
     * @param requireSender If true, require msg.sender == request.user
     * @return user The withdrawal recipient
     * @return stakeAmount The amount to send
     */
    function _claimWithdrawalInternal(
        uint256 requestId,
        bool requireSender
    ) internal returns (address user, uint256 stakeAmount) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        if (requestId >= $.withdrawalQueue.length) {
            revert StakingVault__WithdrawalNotClaimable(requestId);
        }
        if (requestId < $.queueHead) {
            revert StakingVault__WithdrawalAlreadyClaimed(requestId);
        }

        WithdrawalRequest storage request = $.withdrawalQueue[requestId];

        if (requireSender && request.user != msg.sender) {
            revert StakingVault__WithdrawalNotClaimable(requestId);
        }
        if (request.fulfilled) {
            revert StakingVault__WithdrawalAlreadyClaimed(requestId);
        }
        if (!$.withdrawalClaimable[requestId]) {
            revert StakingVault__WithdrawalNotClaimable(requestId);
        }

        user = request.user;
        stakeAmount = request.stakeAmount;

        request.fulfilled = true;
        $.withdrawalClaimable[requestId] = false;
        $.claimableWithdrawalStake -= stakeAmount;
        $.pendingWithdrawalStake -= stakeAmount;

        _advanceQueueHead($);
    }

    /**
     * @notice Advance queueHead past leading fulfilled entries and delete their storage
     * @param $ Storage pointer
     */
    function _advanceQueueHead(
        StakingVaultStorageLib.StakingVaultStorage storage $
    ) internal {
        uint256 advanced;
        while (
            advanced < StakingVaultStorageLib.MAX_ADVANCE_PER_CALL && $.queueHead < $.withdrawalQueue.length
                && $.withdrawalQueue[$.queueHead].fulfilled
        ) {
            delete $.withdrawalQueue[$.queueHead];
            unchecked {
                ++$.queueHead;
                ++advanced;
            }
        }
        if ($.queueProcessHead < $.queueHead) {
            $.queueProcessHead = $.queueHead;
        }
    }

    /**
     * @notice Authorizes an upgrade to a new implementation
     * @dev Required by UUPS pattern. Only DEFAULT_ADMIN_ROLE can authorize upgrades.
     * @param newImplementation Address of the new implementation
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newImplementation.code.length == 0) {
            revert StakingVault__InvalidImplementation(newImplementation);
        }
    }

    function _getMinimumDelegationFeeBips() private view returns (uint16 minDelegationFeeBips) {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();
        (bool success, bytes memory data) = address($.stakingManager)
            .staticcall(abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_STAKING_MANAGER_SETTINGS));
        if (!success || data.length < 160) {
            revert IStakingVault.StakingVault__StakingManagerCallFailed();
        }
        assembly {
            minDelegationFeeBips := mload(add(data, 160))
        }
    }

    /**
     * @notice Cache immutable settings from StakingManager
     * @dev ValidatorManager address and weightToValueFactor are set once during
     *      StakingManager initialization and never change. Caching saves ~2000 gas
     *      per validator/delegator stake lookup.
     *      Also initializes operatorFeeBips to StakingManager's minDelegationFeeBips.
     */
    function _cacheStakingManagerSettings() internal {
        StakingVaultStorageLib.StakingVaultStorage storage $ = StakingVaultStorageLib._getStorage();

        (bool success, bytes memory data) = address($.stakingManager)
            .staticcall(abi.encodeWithSelector(StakingVaultStorageLib.SEL_GET_STAKING_MANAGER_SETTINGS));
        if (!success || data.length < 224) {
            revert StakingVault__InvalidStakingManager();
        }

        address validatorManager;
        uint256 weightToValueFactor;
        uint16 minDelegationFeeBips;
        assembly {
            validatorManager := mload(add(data, 32)) // manager is first field
            minDelegationFeeBips := mload(add(data, 160)) // minDelegationFeeBips is 5th field
            weightToValueFactor := mload(add(data, 224)) // weightToValueFactor is 7th field
        }

        if (validatorManager == address(0) || weightToValueFactor == 0) {
            revert StakingVault__InvalidStakingManager();
        }
        if (uint256(minDelegationFeeBips) > StakingVaultStorageLib.MAX_OPERATOR_FEE_BIPS) {
            revert StakingVault__InvalidStakingManager();
        }

        $.cachedValidatorManager = validatorManager;
        $.cachedWeightToValueFactor = weightToValueFactor;
        // Initialize operatorFeeBips to StakingManager's minimum delegation fee
        $.operatorFeeBips = uint256(minDelegationFeeBips);
    }

    /**
     * @notice Validate that an operations implementation address is safe to store
     * @param impl The candidate implementation address
     */
    function _validateOperationsImpl(
        address impl
    ) private view {
        if (impl.code.length == 0) {
            revert StakingVault__InvalidImplementation(impl);
        }
        if (impl == address(this) || impl == _getERC1967Implementation()) {
            revert StakingVault__InvalidImplementation(impl);
        }
    }

    /**
     * @notice Read the ERC1967 implementation address from storage slot
     * @dev Used to prevent setting operationsImpl to the proxy's implementation (would cause infinite recursion)
     * @return impl The ERC1967 implementation address
     */
    function _getERC1967Implementation() internal view returns (address impl) {
        // ERC1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            impl := sload(slot)
        }
    }

    /**
     * @notice Get exchange rate with virtual offset for first depositor protection
     * @return rate Exchange rate scaled by 1e18
     */
    function _getExchangeRate() internal view returns (uint256 rate) {
        uint256 totalShares = totalSupply() + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        uint256 totalStake = getTotalPooledStake() + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        return (totalStake * 1e18) / totalShares;
    }

    /**
     * @notice Convert stake to LST amount using explicit pre-deposit stake value
     */
    function _stakeToShares(
        uint256 stakeAmount,
        uint256 preDepositTotalStake
    ) internal view returns (uint256 shares) {
        uint256 totalShares = totalSupply() + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        uint256 totalStake = preDepositTotalStake + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        shares = (stakeAmount * totalShares) / totalStake;
    }

    /**
     * @notice Convert shares to stake amount (rounds DOWN)
     */
    function _sharesToStake(
        uint256 shares
    ) internal view returns (uint256 stakeAmount) {
        uint256 totalShares = totalSupply() + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        uint256 totalStake = getTotalPooledStake() + StakingVaultStorageLib.INITIAL_SHARES_OFFSET;
        stakeAmount = (shares * totalStake) / totalShares;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.4.0) (interfaces/draft-IERC1822.sol)

pragma solidity >=0.4.16;

/**
 * @dev ERC-1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
