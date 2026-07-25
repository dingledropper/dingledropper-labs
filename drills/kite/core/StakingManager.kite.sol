abstract contract StakingManager is
    IStakingManager,
    ContextUpgradeable,
    ReentrancyGuardUpgradeable
{
    // solhint-disable private-vars-leading-underscore
    /// @custom:storage-location erc7201:avalanche-icm.storage.StakingManager
    struct StakingManagerStorage {
        IValidatorManager _manager;
        /// @notice The minimum amount of stake required to be a validator.
        uint256 _minimumStakeAmount;
        /// @notice The maximum amount of stake allowed to be a validator.
        uint256 _maximumStakeAmount;
        /// @notice The minimum amount of time in seconds a validator must be staked for. Must be at least {_churnPeriodSeconds}.
        uint64 _minimumStakeDuration;
        /// @notice The minimum delegation fee percentage, in basis points, required to delegate to a validator.
        uint16 _minimumDelegationFeeBips;
        /**
         * @notice A multiplier applied to validator's initial stake amount to determine
         * the maximum amount of stake a validator can have with delegations.
         * Note: Setting this value to 1 would disable delegations to validators, since
         * the maximum stake would be equal to the initial stake.
         */
        uint64 _maximumStakeMultiplier;
        /// @notice The factor used to convert between weight and value.
        uint256 _weightToValueFactor;
        /// @notice The reward calculator for this validator manager.
        IRewardCalculator _rewardCalculator;
        /// @notice The ID of the blockchain that submits uptime proofs. This must be a blockchain validated by the subnetID that this contract manages.
        bytes32 _uptimeBlockchainID;
        /// @notice Maps the validation ID to its requirements.
        mapping(bytes32 validationID => PoSValidatorInfo) _posValidatorInfo;
        /// @notice Maps the delegation ID to the delegator information.
        mapping(bytes32 delegationID => Delegator) _delegatorStakes;
        /// @notice Maps the delegation ID to its pending staking rewards.
        mapping(bytes32 delegationID => uint256) _redeemableDelegatorRewards;
        mapping(bytes32 delegationID => address) _delegatorRewardRecipients;
        /// @notice Maps the validation ID to its pending staking rewards.
        mapping(bytes32 validationID => uint256) _redeemableValidatorRewards;
        /// @notice Maps the validation ID to its reward recipient.
        mapping(bytes32 validationID => address) _rewardRecipients;
    }
    // solhint-enable private-vars-leading-underscore

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.StakingManager")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 public constant STAKING_MANAGER_STORAGE_LOCATION =
        0xafe6c4731b852fc2be89a0896ae43d22d8b24989064d841b2a1586b4d39ab600;

    uint8 public constant MAXIMUM_STAKE_MULTIPLIER_LIMIT = 20;

    uint16 public constant MAXIMUM_DELEGATION_FEE_BIPS = 10000;

    uint16 public constant BIPS_CONVERSION_FACTOR = 10000;

    IWarpMessenger public constant WARP_MESSENGER =
        IWarpMessenger(0x0200000000000000000000000000000000000005);

    error InvalidDelegationFee(uint16 delegationFeeBips);
    error InvalidDelegationID(bytes32 delegationID);
    error InvalidDelegatorStatus(DelegatorStatus status);
    error InvalidRewardRecipient(address rewardRecipient);
    error InvalidStakeAmount(uint256 stakeAmount);
    error InvalidMinStakeDuration(uint64 minStakeDuration);
    error InvalidStakeMultiplier(uint8 maximumStakeMultiplier);
    error MaxWeightExceeded(uint64 newValidatorWeight);
    error MinStakeDurationNotPassed(uint64 endTime);
    error UnauthorizedOwner(address sender);
    error ValidatorNotPoS(bytes32 validationID);
    error ValidatorIneligibleForRewards(bytes32 validationID);
    error DelegatorIneligibleForRewards(bytes32 delegationID);
    error ZeroWeightToValueFactor();
    error InvalidUptimeBlockchainID(bytes32 uptimeBlockchainID);
    error NoRewardsToClaim();

    error InvalidWarpOriginSenderAddress(address senderAddress);
    error InvalidWarpSourceChainID(bytes32 sourceChainID);
    error UnexpectedValidationID(
        bytes32 validationID,
        bytes32 expectedValidationID
    );
    error InvalidValidatorStatus(ValidatorStatus status);
    error InvalidNonce(uint64 nonce);
    error InvalidWarpMessage();
    error ZeroAddress();
    error RewardClaimFailed();

    // solhint-disable ordering
    /**
     * @dev This storage is visible to child contracts for convenience.
     *      External getters would be better practice, but code size limitations are preventing this.
     *      Child contracts should probably never write to this storage.
     */
    function _getStakingManagerStorage()
        internal
        pure
        returns (StakingManagerStorage storage $)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := STAKING_MANAGER_STORAGE_LOCATION
        }
    }

    // ============================================
    // Modifiers
    // ============================================

    /**
     * @dev Validates that the caller is the validator owner. Reverts if not.
     */
    modifier onlyValidatorOwner(bytes32 validationID) {
        if (
            _getStakingManagerStorage()._posValidatorInfo[validationID].owner !=
            _msgSender()
        ) {
            revert UnauthorizedOwner(_msgSender());
        }
        _;
    }

    /**
     * @dev Validates that the caller is the delegator owner. Reverts if not.
     */
    modifier onlyDelegatorOwner(bytes32 delegationID) {
        if (
            _getStakingManagerStorage()._delegatorStakes[delegationID].owner !=
            _msgSender()
        ) {
            revert UnauthorizedOwner(_msgSender());
        }
        _;
    }

    // ============================================
    // Internal Helper Functions
    // ============================================

    /**
     * @dev Returns the reward recipient for a validator, falling back to owner if not set.
     */
    function _getValidatorRewardRecipient(
        bytes32 validationID
    ) internal view returns (address) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        address recipient = $._rewardRecipients[validationID];
        return
            recipient != address(0)
                ? recipient
                : $._posValidatorInfo[validationID].owner;
    }

    /**
     * @dev Returns the reward recipient for a delegator, falling back to owner if not set.
     */
    function _getDelegatorRewardRecipient(
        bytes32 delegationID
    ) internal view returns (address) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        address recipient = $._delegatorRewardRecipients[delegationID];
        return
            recipient != address(0)
                ? recipient
                : $._delegatorStakes[delegationID].owner;
    }

    /**
     * @dev Internal function version for use in complex control flows.
     */
    function _checkValidatorOwner(bytes32 validationID) internal view {
        if (
            _getStakingManagerStorage()._posValidatorInfo[validationID].owner !=
            _msgSender()
        ) {
            revert UnauthorizedOwner(_msgSender());
        }
    }

    /**
     * @dev Internal function version for use in complex control flows.
     */
    function _checkDelegatorOwner(bytes32 delegationID) internal view {
        if (
            _getStakingManagerStorage()._delegatorStakes[delegationID].owner !=
            _msgSender()
        ) {
            revert UnauthorizedOwner(_msgSender());
        }
    }

    // solhint-disable-next-line func-name-mixedcase
    function __StakingManager_init(
        StakingManagerSettings calldata settings
    ) internal onlyInitializing {
        __ReentrancyGuard_init();
        __StakingManager_init_unchained({
            manager: settings.manager,
            minimumStakeAmount: settings.minimumStakeAmount,
            maximumStakeAmount: settings.maximumStakeAmount,
            minimumStakeDuration: settings.minimumStakeDuration,
            minimumDelegationFeeBips: settings.minimumDelegationFeeBips,
            maximumStakeMultiplier: settings.maximumStakeMultiplier,
            weightToValueFactor: settings.weightToValueFactor,
            rewardCalculator: settings.rewardCalculator,
            uptimeBlockchainID: settings.uptimeBlockchainID
        });
    }

    // solhint-disable-next-line func-name-mixedcase
    function __StakingManager_init_unchained(
        IValidatorManager manager,
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint64 minimumStakeDuration,
        uint16 minimumDelegationFeeBips,
        uint8 maximumStakeMultiplier,
        uint256 weightToValueFactor,
        IRewardCalculator rewardCalculator,
        bytes32 uptimeBlockchainID
    ) internal onlyInitializing {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        if (
            minimumDelegationFeeBips == 0 ||
            minimumDelegationFeeBips > MAXIMUM_DELEGATION_FEE_BIPS
        ) {
            revert InvalidDelegationFee(minimumDelegationFeeBips);
        }
        if (minimumStakeAmount > maximumStakeAmount) {
            revert InvalidStakeAmount(minimumStakeAmount);
        }
        if (
            maximumStakeMultiplier == 0 ||
            maximumStakeMultiplier > MAXIMUM_STAKE_MULTIPLIER_LIMIT
        ) {
            revert InvalidStakeMultiplier(maximumStakeMultiplier);
        }
        if (address(manager) == address(0)) {
            revert ZeroAddress();
        }
        if (address(rewardCalculator) == address(0)) {
            revert ZeroAddress();
        }

        // Minimum stake duration should be at least one churn period in order to prevent churn tracker abuse.
        if (minimumStakeDuration < manager.getChurnPeriodSeconds()) {
            revert InvalidMinStakeDuration(minimumStakeDuration);
        }
        if (weightToValueFactor == 0) {
            revert ZeroWeightToValueFactor();
        }
        if (uptimeBlockchainID == bytes32(0)) {
            revert InvalidUptimeBlockchainID(uptimeBlockchainID);
        }

        $._manager = manager;
        $._minimumStakeAmount = minimumStakeAmount;
        $._maximumStakeAmount = maximumStakeAmount;
        $._minimumStakeDuration = minimumStakeDuration;
        $._minimumDelegationFeeBips = minimumDelegationFeeBips;
        $._maximumStakeMultiplier = maximumStakeMultiplier;
        $._weightToValueFactor = weightToValueFactor;
        $._rewardCalculator = rewardCalculator;
        $._uptimeBlockchainID = uptimeBlockchainID;
    }

    /**
     * @notice See {IStakingManager-submitUptimeProof}.
     */
    function submitUptimeProof(
        bytes32 validationID,
        uint32 messageIndex
    ) external {
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }
        ValidatorStatus status = _getStakingManagerStorage()
            ._manager
            .getValidator(validationID)
            .status;
        if (status != ValidatorStatus.Active) {
            revert InvalidValidatorStatus(status);
        }

        // Uptime proofs include the absolute number of seconds the validator has been active.
        _updateUptime(validationID, messageIndex);
    }

    /**
     * @notice See {IStakingManager-claimValidatorRewards}.
     * Claims accumulated rewards for a validator.
     * @param validationID The ID of the validation period.
     * @param includeUptimeProof Whether to include an uptime proof to update the uptime.
     * @param messageIndex The index of the Warp message containing the uptime proof (ignored if includeUptimeProof is false).
     */
    function claimValidatorRewards(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant returns (uint256 reward) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }

        // Verify the caller is the owner
        _checkValidatorOwner(validationID);
        address rewardRecipient = _getValidatorRewardRecipient(validationID);

        Validator memory validator = $._manager.getValidator(validationID);

        if (validator.status == ValidatorStatus.Active) {
            // Active validator: calculate and claim incremental rewards
            reward = _claimActiveValidatorRewards(
                validationID,
                rewardRecipient,
                validator,
                includeUptimeProof,
                messageIndex
            );
        } else if (validator.status == ValidatorStatus.Completed) {
            // Completed validator: claim any pending redeemable rewards
            // (e.g., rewards that failed to distribute during completeValidatorRemoval,
            // or delegation fees accumulated after initiateValidatorRemoval)
            reward = $._redeemableValidatorRewards[validationID];
            if (reward == 0) {
                revert NoRewardsToClaim();
            }
            bool success = _reward(rewardRecipient, reward);
            // Only clear rewards if distribution succeeded
            // If failed, rewards remain claimable via claimValidatorRewards
            if (success) {
                delete $._redeemableValidatorRewards[validationID];
                emit ValidatorRewardClaimed(
                    validationID,
                    rewardRecipient,
                    reward
                );
            } else {
                revert RewardClaimFailed();
            }
        } else {
            // PendingRemoved: rewards already calculated in initiateValidatorRemoval, wait for completion
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /**
     * @dev Internal function to claim rewards for an active validator
     */
    function _claimActiveValidatorRewards(
        bytes32 validationID,
        address rewardRecipient,
        Validator memory validator,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal returns (uint256 reward) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Get uptime and calculate reward
        (uint64 currentUptime, uint64 currentTime) = _getUpdatedUptime(
            validationID,
            validator.status,
            includeUptimeProof,
            messageIndex
        );

        uint64 lastClaimTime = $
            ._posValidatorInfo[validationID]
            .lastRewardClaimTime;
        uint64 lastClaimUptime = $
            ._posValidatorInfo[validationID]
            .lastClaimUptimeSeconds;
        if (lastClaimTime == 0) {
            lastClaimTime = validator.startTime;
        }

        // Calculate incremental staking reward
        uint256 stakingReward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(validator.startingWeight),
            lastClaimTime: lastClaimTime,
            currentTime: currentTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: currentUptime,
            validatorStartTime: validator.startTime
        });

        // Get accumulated delegation fees (commission from delegators)
        uint256 delegationFees = $._redeemableValidatorRewards[validationID];

        // Total reward = staking reward + delegation fees
        reward = stakingReward + delegationFees;

        // Revert if no rewards to claim
        if (reward == 0) {
            revert NoRewardsToClaim();
        }

        $._posValidatorInfo[validationID].lastRewardClaimTime = currentTime;
        $
            ._posValidatorInfo[validationID]
            .lastClaimUptimeSeconds = currentUptime;

         delete $._redeemableValidatorRewards[validationID];
        if (delegationFees > 0) {
            emit DelegationFeesWithdrawn(
                validationID,
                rewardRecipient,
                delegationFees
            );
        }

        // Transfer rewards after state update
        bool success = _reward(rewardRecipient, reward);
        if (!success) {
            revert RewardClaimFailed();
        }

        emit ValidatorRewardClaimed(
            validationID,
            rewardRecipient,
            stakingReward
        );
    }

    /**
     * @notice See {IStakingManager-claimDelegatorRewards}.
     * Claims accumulated rewards for a delegator.
     * - For Active delegators: calculates and claims incremental rewards
     * - For completed delegators: claims any pending rewards that failed to distribute during removal
     * @param delegationID The ID of the delegation.
     * @param includeUptimeProof Whether to include an uptime proof to update the uptime.
     * @param messageIndex The index of the Warp message containing the uptime proof (ignored if includeUptimeProof is false).
     */
    function claimDelegatorRewards(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant returns (uint256 reward) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator storage delegator = $._delegatorStakes[delegationID];

        if (delegator.status == DelegatorStatus.Active) {
            // Active delegator: calculate and claim incremental rewards
            reward = _claimActiveDelegatorRewards(
                delegationID,
                delegator,
                includeUptimeProof,
                messageIndex
            );
        } else if (delegator.status == DelegatorStatus.Unknown) {
            // Delegator has completed removal
            // check for unclaimed rewards due to reward distribution failure
            uint256 pendingRewards = $._redeemableDelegatorRewards[
                delegationID
            ];
            if (pendingRewards == 0) {
                revert NoRewardsToClaim();
            }

            // Use preserved delegator data for permission check and commission calculation
            bytes32 storedValidationID = delegator.validationID;
            if (storedValidationID == bytes32(0)) {
                // This should not happen if completeDelegatorRemoval was called correctly
                revert InvalidDelegationID(delegationID);
            }

            // Only the owner can claim
            _checkDelegatorOwner(delegationID);
            address rewardRecipient = _getDelegatorRewardRecipient(
                delegationID
            );

            // Attempt to distribute pending rewards
            (uint256 delegationRewards, ) = _withdrawDelegationRewards(
                rewardRecipient,
                delegationID,
                storedValidationID
            );

            // Revert if distribution failed
            if (delegationRewards == 0 && pendingRewards > 0) {
                revert RewardClaimFailed();
            }
            reward = delegationRewards;
            delete $._delegatorStakes[delegationID];
        } else {
            // PendingAdded or PendingRemoved: cannot claim
            revert InvalidDelegatorStatus(delegator.status);
        }
    }

    /**
     * @dev Internal function to claim rewards for an active delegator
     */
    function _claimActiveDelegatorRewards(
        bytes32 delegationID,
        Delegator storage delegator,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal returns (uint256 reward) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Verify the caller is the owner
        _checkDelegatorOwner(delegationID);
        address rewardRecipient = _getDelegatorRewardRecipient(delegationID);

        bytes32 validationID = delegator.validationID;
        Validator memory validator = $._manager.getValidator(validationID);

        // Get uptime and calculate reward
        (uint64 currentUptime, uint64 currentTime) = _getUpdatedUptime(
            validationID,
            validator.status,
            includeUptimeProof,
            messageIndex
        );

        // If validator has exited (PendingRemoved or Completed), use validator.endTime as cutoff
        // This ensures delegators get correct rewards even if they claim after validator exits
        if (
            validator.status == ValidatorStatus.PendingRemoved ||
            validator.status == ValidatorStatus.Completed
        ) {
            currentTime = validator.endTime;
        }

        uint64 lastClaimTime = delegator.lastRewardClaimTime;
        uint64 lastClaimUptime = delegator.lastClaimUptimeSeconds;
        if (lastClaimTime == 0) {
            lastClaimTime = delegator.startTime;
        }

        // If already claimed up to or past the cutoff time, no more rewards
        if (lastClaimTime >= currentTime) {
            revert NoRewardsToClaim();
        }

        uint256 grossReward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(delegator.weight),
            lastClaimTime: lastClaimTime,
            currentTime: currentTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: currentUptime,
            validatorStartTime: validator.startTime
        });

        // Revert if no rewards to claim (grossReward == 0)
        if (grossReward == 0) {
            revert NoRewardsToClaim();
        }

        // Calculate and allocate commission (validator fee)
        uint256 validatorFee = (grossReward *
            $._posValidatorInfo[validationID].delegationFeeBips) /
            BIPS_CONVERSION_FACTOR;
        reward = grossReward - validatorFee;

        delegator.lastRewardClaimTime = currentTime;
        delegator.lastClaimUptimeSeconds = currentUptime;

        if (validatorFee > 0) {
            $._redeemableValidatorRewards[validationID] += validatorFee;
            emit DelegationFeesAccrued(
                validationID,
                delegationID,
                validatorFee
            );
        }

        // Transfer rewards after state update
        if (reward > 0) {
            bool success = _reward(rewardRecipient, reward);
            if (!success) {
                revert RewardClaimFailed();
            }
        }

        emit DelegatorRewardClaimed(delegationID, rewardRecipient, reward);
    }

    /**
     * @dev Gets the updated uptime for a validator. If the validator is active and includeUptimeProof is true,
     * updates uptime with the proof. Otherwise, returns the stored uptime.
     */
    function _getUpdatedUptime(
        bytes32 validationID,
        ValidatorStatus status,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal returns (uint64 currentUptime, uint64 currentTime) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Update uptime from the provided proof if requested and validator is active
        if (status == ValidatorStatus.Active && includeUptimeProof) {
            currentUptime = _updateUptime(validationID, messageIndex);
        } else {
            currentUptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }
        currentTime = uint64(block.timestamp);
    }

    /**
     * @notice See {IStakingManager-initiateValidatorRemoval}.
     */
    function initiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant {
        _initiateValidatorRemovalWithCheck(
            validationID,
            includeUptimeProof,
            messageIndex
        );
    }

    function _initiateValidatorRemovalWithCheck(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        // With incremental reward claiming, reward can be 0 if just claimed, so no need to check
        _initiatePoSValidatorRemoval(
            validationID,
            includeUptimeProof,
            messageIndex
        );
    }

    /**
     * @notice See {IStakingManager-forceInitiateValidatorRemoval}.
     * @dev This function is kept for backwards compatibility. With incremental reward claiming,
     *      it behaves the same as initiateValidatorRemoval.
     */
    function forceInitiateValidatorRemoval(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        _initiatePoSValidatorRemoval(
            validationID,
            includeUptimeProof,
            messageIndex
        );
    }

    /**
     * @notice See {IStakingManager-changeValidatorRewardRecipient}.
     */
    function changeValidatorRewardRecipient(
        bytes32 validationID,
        address rewardRecipient
    ) external onlyValidatorOwner(validationID) {
        if (rewardRecipient == address(0)) {
            revert InvalidRewardRecipient(rewardRecipient);
        }

        StakingManagerStorage storage $ = _getStakingManagerStorage();
        address currentRecipient = $._rewardRecipients[validationID];
        $._rewardRecipients[validationID] = rewardRecipient;

        emit ValidatorRewardRecipientChanged(
            validationID,
            rewardRecipient,
            currentRecipient
        );
    }

    /**
     * @notice See {IStakingManager-changeDelegatorRewardRecipient}.
     */
    function changeDelegatorRewardRecipient(
        bytes32 delegationID,
        address rewardRecipient
    ) external onlyDelegatorOwner(delegationID) {
        if (rewardRecipient == address(0)) {
            revert InvalidRewardRecipient(rewardRecipient);
        }

        StakingManagerStorage storage $ = _getStakingManagerStorage();
        address currentRecipient = $._delegatorRewardRecipients[delegationID];
        $._delegatorRewardRecipients[delegationID] = rewardRecipient;

        emit DelegatorRewardRecipientChanged(
            delegationID,
            rewardRecipient,
            currentRecipient
        );
    }

    /**
     * @dev Helper function that initiates the end of a PoS validation period.
     * Calculates remaining rewards from last claim to end time and stores them for later distribution.
     */
    function _initiatePoSValidatorRemoval(
        bytes32 validationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        $._manager.initiateValidatorRemoval(validationID);

        // The validator must be fetched after the removal has been initiated, since the above call modifies
        // the validator's state.
        Validator memory validator = $._manager.getValidator(validationID);

        // Non-PoS validators are required to bootstrap the network, but are not eligible for rewards.
        if (!_isPoSValidator(validationID)) {
            return;
        }

        // PoS validations can only be ended by their owners.
        _checkValidatorOwner(validationID);

        // Check that minimum stake duration has passed.
        if (
            validator.endTime <
            validator.startTime +
                $._posValidatorInfo[validationID].minStakeDuration
        ) {
            revert MinStakeDurationNotPassed(validator.endTime);
        }

        // Uptime proofs include the absolute number of seconds the validator has been active.
        uint64 uptimeSeconds;
        if (includeUptimeProof) {
            uptimeSeconds = _updateUptime(validationID, messageIndex);
        } else {
            uptimeSeconds = $._posValidatorInfo[validationID].uptimeSeconds;
        }

        // Calculate remaining reward from last claim (or start) to end
        PoSValidatorInfo storage posInfo = $._posValidatorInfo[validationID];
        uint64 lastClaimTime = posInfo.lastRewardClaimTime;
        uint64 lastClaimUptime = posInfo.lastClaimUptimeSeconds;

        // If never claimed before, use validator start time
        if (lastClaimTime == 0) {
            lastClaimTime = validator.startTime;
            lastClaimUptime = 0;
        }

        uint256 reward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(validator.startingWeight),
            lastClaimTime: lastClaimTime,
            currentTime: validator.endTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: uptimeSeconds,
            validatorStartTime: validator.startTime
        });

        $._redeemableValidatorRewards[validationID] += reward;
    }

    /**
     * @notice See {IStakingManager-completeValidatorRemoval}.
     * Extends the functionality of {ACP99Manager-completeValidatorRemoval} by unlocking staking rewards.
     */
    function completeValidatorRemoval(
        uint32 messageIndex
    ) external nonReentrant returns (bytes32) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Check if the validator has been already been removed from the validator manager.
        bytes32 validationID = $._manager.completeValidatorRemoval(
            messageIndex
        );
        Validator memory validator = $._manager.getValidator(validationID);

        // Return now if this was originally a PoA validator that was later migrated to this PoS manager,
        // or the validator was part of the initial validator set.
        if (!_isPoSValidator(validationID)) {
            return validationID;
        }

        address owner = $._posValidatorInfo[validationID].owner;
        address rewardRecipient = _getValidatorRewardRecipient(validationID);

        // Get the rewards amount before withdrawal for event emission
        uint256 rewards = $._redeemableValidatorRewards[validationID];

        // The validator can either be Completed or Invalidated here. We only grant rewards for Completed.
        if (validator.status == ValidatorStatus.Completed) {
            _withdrawValidationRewards(rewardRecipient, validationID);
        } else {
            // If invalidated, no rewards are given
            rewards = 0;
        }

        // The stake is unlocked whether the validation period is completed or invalidated.
        uint256 stakeAmount = weightToValue(validator.startingWeight);
        _unlock(owner, stakeAmount);

        emit CompletedStakingValidatorRemoval(
            validationID,
            stakeAmount,
            rewards
        );

        return validationID;
    }

    /**
     * @dev Helper function that extracts the uptime from a ValidationUptimeMessage Warp message
     * If the uptime is greater than the stored uptime, update the stored uptime.
     */
    function _updateUptime(
        bytes32 validationID,
        uint32 messageIndex
    ) internal returns (uint64) {
        (WarpMessage memory warpMessage, bool valid) = WARP_MESSENGER
            .getVerifiedWarpMessage(messageIndex);
        if (!valid) {
            revert InvalidWarpMessage();
        }

        StakingManagerStorage storage $ = _getStakingManagerStorage();
        // The uptime proof must be from the specifed uptime blockchain
        if (warpMessage.sourceChainID != $._uptimeBlockchainID) {
            revert InvalidWarpSourceChainID(warpMessage.sourceChainID);
        }

        // The sender is required to be the zero address so that we know the validator node
        // signed the proof directly, rather than as an arbitrary on-chain message
        if (warpMessage.originSenderAddress != address(0)) {
            revert InvalidWarpOriginSenderAddress(
                warpMessage.originSenderAddress
            );
        }

        (bytes32 uptimeValidationID, uint64 uptime) = ValidatorMessages
            .unpackValidationUptimeMessage(warpMessage.payload);
        if (validationID != uptimeValidationID) {
            revert UnexpectedValidationID(uptimeValidationID, validationID);
        }

        if (uptime > $._posValidatorInfo[validationID].uptimeSeconds) {
            $._posValidatorInfo[validationID].uptimeSeconds = uptime;
            emit UptimeUpdated(validationID, uptime);
        } else {
            uptime = $._posValidatorInfo[validationID].uptimeSeconds;
        }

        return uptime;
    }

    /**
     * @notice Initiates validator registration. Extends the functionality of {ACP99Manager-_initiateValidatorRegistration}
     * by locking stake and setting staking and delegation parameters.
     * @param delegationFeeBips The delegation fee in basis points.
     * @param minStakeDuration The minimum stake duration in seconds.
     * @param stakeAmount The amount of stake to lock.
     */
    function _initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        uint256 stakeAmount,
        address rewardRecipient
    ) internal virtual returns (bytes32) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        // Validate and save the validator requirements
        if (
            delegationFeeBips < $._minimumDelegationFeeBips ||
            delegationFeeBips > MAXIMUM_DELEGATION_FEE_BIPS
        ) {
            revert InvalidDelegationFee(delegationFeeBips);
        }

        if (minStakeDuration < $._minimumStakeDuration) {
            revert InvalidMinStakeDuration(minStakeDuration);
        }

        // Ensure the weight is within the valid range.
        if (
            stakeAmount < $._minimumStakeAmount ||
            stakeAmount > $._maximumStakeAmount
        ) {
            revert InvalidStakeAmount(stakeAmount);
        }

        if (rewardRecipient == address(0)) {
            revert InvalidRewardRecipient(rewardRecipient);
        }

        // Lock the stake in the contract.
        uint256 lockedValue = _lock(stakeAmount);

        uint64 weight = valueToWeight(lockedValue);
        bytes32 validationID = $._manager.initiateValidatorRegistration({
            nodeID: nodeID,
            blsPublicKey: blsPublicKey,
            remainingBalanceOwner: remainingBalanceOwner,
            disableOwner: disableOwner,
            weight: weight
        });

        address owner = _msgSender();

        $._posValidatorInfo[validationID].owner = owner;
        $._posValidatorInfo[validationID].delegationFeeBips = delegationFeeBips;
        $._posValidatorInfo[validationID].minStakeDuration = minStakeDuration;
        $._posValidatorInfo[validationID].uptimeSeconds = 0;
        $._rewardRecipients[validationID] = rewardRecipient;

        emit InitiatedStakingValidatorRegistration({
            validationID: validationID,
            owner: owner,
            delegationFeeBips: delegationFeeBips,
            minStakeDuration: minStakeDuration,
            rewardRecipient: rewardRecipient,
            stakeAmount: stakeAmount
        });

        return validationID;
    }

    /**
     * @notice See {IStakingManager-completeValidatorRegistration}.
     */
    function completeValidatorRegistration(
        uint32 messageIndex
    ) external returns (bytes32) {
        return
            _getStakingManagerStorage()._manager.completeValidatorRegistration(
                messageIndex
            );
    }

    /**
     * @notice Converts a token value to a weight.
     * @param value Token value to convert.
     */
    function valueToWeight(uint256 value) public view returns (uint64) {
        uint256 weight = value /
            _getStakingManagerStorage()._weightToValueFactor;
        if (weight == 0 || weight > type(uint64).max) {
            revert InvalidStakeAmount(value);
        }
        return uint64(weight);
    }

    /**
     * @notice Converts a weight to a token value.
     * @param weight weight to convert.
     */
    function weightToValue(uint64 weight) public view returns (uint256) {
        return
            uint256(weight) * _getStakingManagerStorage()._weightToValueFactor;
    }

    /**
     * @notice Returns the settings used to initialize the StakingManager
     */
    function getStakingManagerSettings()
        public
        view
        returns (StakingManagerSettings memory)
    {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        return
            StakingManagerSettings({
                manager: $._manager,
                minimumStakeAmount: $._minimumStakeAmount,
                maximumStakeAmount: $._maximumStakeAmount,
                minimumStakeDuration: $._minimumStakeDuration,
                minimumDelegationFeeBips: $._minimumDelegationFeeBips,
                maximumStakeMultiplier: uint8($._maximumStakeMultiplier),
                weightToValueFactor: $._weightToValueFactor,
                rewardCalculator: $._rewardCalculator,
                uptimeBlockchainID: $._uptimeBlockchainID
            });
    }

    /**
     * @notice Returns the PoS validator information for the given validationID
     * See {ValidatorManager-getValidator} to retreive information about the validator not specific to PoS
     */
    function getStakingValidator(
        bytes32 validationID
    ) public view returns (PoSValidatorInfo memory) {
        return _getStakingManagerStorage()._posValidatorInfo[validationID];
    }

    /**
     * @notice Returns the reward recipient and claimable reward amount for the given validationID
     * @return The current validation reward recipient
     * @return The current claimable validation reward amount
     */
    function getValidatorRewardInfo(
        bytes32 validationID
    ) public view returns (address, uint256) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        return (
            $._rewardRecipients[validationID],
            $._redeemableValidatorRewards[validationID]
        );
    }

    /**
     * @notice Returns the delegator information for the given delegationID
     */
    function getDelegatorInfo(
        bytes32 delegationID
    ) public view returns (Delegator memory) {
        return _getStakingManagerStorage()._delegatorStakes[delegationID];
    }

    /**
     * @notice Returns the reward recipient and claimable reward amount for the given delegationID
     * @return The current delegation reward recipient
     * @return The current claimable delegation reward amount
     */
    function getDelegatorRewardInfo(
        bytes32 delegationID
    ) public view returns (address, uint256) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        return (
            $._delegatorRewardRecipients[delegationID],
            $._redeemableDelegatorRewards[delegationID]
        );
    }

    /**
     * @notice Returns the estimated pending rewards for a validator using stored uptime.
     * @dev This is an estimate based on the last stored uptime value. The actual rewards
     * may differ slightly when claimed with a fresh uptime proof.
     * @param validationID The validation ID to query
     * @return stakingReward The estimated staking reward from validator's own stake
     * @return delegationFees The accumulated delegation fees (commission from delegators)
     * @return totalReward The total estimated pending reward (stakingReward + delegationFees)
     */
    function getValidatorPendingRewards(
        bytes32 validationID
    )
        public
        view
        returns (
            uint256 stakingReward,
            uint256 delegationFees,
            uint256 totalReward
        )
    {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Validator memory validator = $._manager.getValidator(validationID);

        // Only active validators can have pending rewards calculated this way
        if (validator.status != ValidatorStatus.Active) {
            // For non-active validators, return only the stored redeemable rewards
            delegationFees = $._redeemableValidatorRewards[validationID];
            return (0, delegationFees, delegationFees);
        }

        // Use stored uptime values
        uint64 currentUptime = $._posValidatorInfo[validationID].uptimeSeconds;
        uint64 currentTime = uint64(block.timestamp);

        uint64 lastClaimTime = $
            ._posValidatorInfo[validationID]
            .lastRewardClaimTime;
        uint64 lastClaimUptime = $
            ._posValidatorInfo[validationID]
            .lastClaimUptimeSeconds;

        if (lastClaimTime == 0) {
            lastClaimTime = validator.startTime;
        }

        // Calculate staking reward
        stakingReward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(validator.startingWeight),
            lastClaimTime: lastClaimTime,
            currentTime: currentTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: currentUptime,
            validatorStartTime: validator.startTime
        });

        // Get accumulated delegation fees
        delegationFees = $._redeemableValidatorRewards[validationID];

        totalReward = stakingReward + delegationFees;
    }

    /**
     * @notice Returns the estimated pending rewards for a delegator using stored uptime.
     * @dev This is an estimate based on the last stored uptime value. The actual rewards
     * may differ slightly when claimed with a fresh uptime proof.
     * @param delegationID The delegation ID to query
     * @return grossReward The gross reward before validator commission
     * @return validatorFee The validator's commission fee
     * @return netReward The net reward after deducting validator commission
     */
    function getDelegatorPendingRewards(
        bytes32 delegationID
    )
        public
        view
        returns (uint256 grossReward, uint256 validatorFee, uint256 netReward)
    {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        // Only active delegators can have pending rewards calculated
        if (delegator.status != DelegatorStatus.Active) {
            // For non-active delegators, return stored redeemable rewards (no commission deduction)
            uint256 redeemable = $._redeemableDelegatorRewards[delegationID];
            return (redeemable, 0, redeemable);
        }

        bytes32 validationID = delegator.validationID;
        Validator memory validator = $._manager.getValidator(validationID);

        // Use stored uptime values
        uint64 currentUptime = $._posValidatorInfo[validationID].uptimeSeconds;
        uint64 currentTime = uint64(block.timestamp);

        // If validator has exited, use validator.endTime as cutoff
        if (
            validator.status == ValidatorStatus.PendingRemoved ||
            validator.status == ValidatorStatus.Completed
        ) {
            currentTime = validator.endTime;
        }

        uint64 lastClaimTime = delegator.lastRewardClaimTime;
        uint64 lastClaimUptime = delegator.lastClaimUptimeSeconds;

        if (lastClaimTime == 0) {
            lastClaimTime = delegator.startTime;
        }

        // If already claimed up to or past the cutoff time, no pending rewards
        if (lastClaimTime >= currentTime) {
            return (0, 0, 0);
        }

        // Calculate gross reward
        grossReward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(delegator.weight),
            lastClaimTime: lastClaimTime,
            currentTime: currentTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: currentUptime,
            validatorStartTime: validator.startTime
        });

        // Calculate validator commission
        validatorFee =
            (grossReward * $._posValidatorInfo[validationID].delegationFeeBips) /
            BIPS_CONVERSION_FACTOR;

        netReward = grossReward - validatorFee;
    }

    /**
     * @notice Locks tokens in this contract.
     * @param value Number of tokens to lock.
     */
    function _lock(uint256 value) internal virtual returns (uint256);

    /**
     * @notice Unlocks token to a specific address.
     * @param to Address to send token to.
     * @param value Number of tokens to lock.
     */
    function _unlock(address to, uint256 value) internal virtual;

    /**
     * @notice Initiates delegator registration by updating the validator's weight and storing the delegation information.
     * Extends the functionality of {ACP99Manager-initiateValidatorWeightUpdate} by locking delegation stake.
     * @param validationID The ID of the validator to delegate to.
     * @param delegatorAddress The address of the delegator.
     * @param delegationAmount The amount of stake to delegate.
     * @param rewardRecipient The address of the reward recipient.
     */
    function _initiateDelegatorRegistration(
        bytes32 validationID,
        address delegatorAddress,
        uint256 delegationAmount,
        address rewardRecipient
    ) internal returns (bytes32) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        uint64 weight = valueToWeight(_lock(delegationAmount));

        // Check that the validation ID is a PoS validator
        if (!_isPoSValidator(validationID)) {
            revert ValidatorNotPoS(validationID);
        }

        if (rewardRecipient == address(0)) {
            revert InvalidRewardRecipient(rewardRecipient);
        }

        // Update the validator weight
        uint64 newValidatorWeight;
        {
            Validator memory validator = $._manager.getValidator(validationID);
            newValidatorWeight = validator.weight + weight;
            if (
                newValidatorWeight >
                validator.startingWeight * $._maximumStakeMultiplier
            ) {
                revert MaxWeightExceeded(newValidatorWeight);
            }
        }

        (uint64 nonce, bytes32 messageID) = $
            ._manager
            .initiateValidatorWeightUpdate(validationID, newValidatorWeight);

        bytes32 delegationID = keccak256(abi.encodePacked(validationID, nonce));
        // Store the delegation information. Set the delegator status to pending added,
        // so that it can be properly started in the complete step, even if the delivered
        // nonce is greater than the nonce used to initiate registration.
        $._delegatorStakes[delegationID].status = DelegatorStatus.PendingAdded;
        $._delegatorStakes[delegationID].owner = delegatorAddress;
        $._delegatorStakes[delegationID].validationID = validationID;
        $._delegatorStakes[delegationID].weight = weight;
        $._delegatorStakes[delegationID].startTime = 0;
        $._delegatorStakes[delegationID].startingNonce = nonce;
        $._delegatorStakes[delegationID].endingNonce = 0;
        $._delegatorRewardRecipients[delegationID] = rewardRecipient;

        emit InitiatedDelegatorRegistration({
            delegationID: delegationID,
            validationID: validationID,
            delegatorAddress: delegatorAddress,
            nonce: nonce,
            validatorWeight: newValidatorWeight,
            delegatorWeight: weight,
            setWeightMessageID: messageID,
            rewardRecipient: rewardRecipient,
            stakeAmount: delegationAmount
        });
        return delegationID;
    }

    /**
     * @notice See {IStakingManager-completeDelegatorRegistration}.
     * Extends the functionality of {ACP99Manager-completeValidatorWeightUpdate} by updating the delegation status.
     */
    function completeDelegatorRegistration(
        bytes32 delegationID,
        uint32 messageIndex,
        uint32 uptimeMessageIndex
    ) external {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;
        Validator memory validator = $._manager.getValidator(validationID);

        // Ensure the delegator is pending added. Since anybody can call this function once
        // delegator registration has been initiated, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingAdded) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        // In the case where the validator has completed its validation period, we can no
        // longer stake and should move our status directly to completed and return the stake.
        if (validator.status == ValidatorStatus.Completed) {
            return _completeDelegatorRemoval(delegationID);
        }

        // If we've already received a weight update with a nonce greater than the delegation's starting nonce,
        // then there's no requirement to include an ICM message in this function call.
        if (validator.receivedNonce < delegator.startingNonce) {
            (bytes32 messageValidationID, uint64 nonce) = $
                ._manager
                .completeValidatorWeightUpdate(messageIndex);

            if (validationID != messageValidationID) {
                revert UnexpectedValidationID(
                    messageValidationID,
                    validationID
                );
            }
            if (nonce < delegator.startingNonce) {
                revert InvalidNonce(nonce);
            }
        }

        uint64 currentUptime = _updateUptime(validationID, uptimeMessageIndex);

        // Update the delegation status
        $._delegatorStakes[delegationID].status = DelegatorStatus.Active;
        $._delegatorStakes[delegationID].startTime = uint64(block.timestamp);
        $._delegatorStakes[delegationID].lastClaimUptimeSeconds = currentUptime;

        emit CompletedDelegatorRegistration({
            delegationID: delegationID,
            validationID: validationID,
            startTime: uint64(block.timestamp)
        });
    }

    /**
     * @notice See {IStakingManager-initiateDelegatorRemoval}.
     */
    function initiateDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external nonReentrant {
        _initiateDelegatorRemovalWithCheck(
            delegationID,
            includeUptimeProof,
            messageIndex
        );
    }

    function _initiateDelegatorRemovalWithCheck(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal {
        // With incremental reward claiming, reward can be 0 if just claimed, so no need to check
        _initiateDelegatorRemoval(
            delegationID,
            includeUptimeProof,
            messageIndex
        );
    }

    /**
     * @notice See {IStakingManager-forceInitiateDelegatorRemoval}.
     */
    function forceInitiateDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) external {
        // Ignore the return value here to force end delegation, regardless of possible missed rewards
        _initiateDelegatorRemoval(
            delegationID,
            includeUptimeProof,
            messageIndex
        );
    }

    /**
     * @dev Helper function that initiates the end of a PoS delegation period.
     * Returns false if it is possible for the delegator to claim rewards, but it is not eligible.
     * Returns true otherwise.
     */
    function _initiateDelegatorRemoval(
        bytes32 delegationID,
        bool includeUptimeProof,
        uint32 messageIndex
    ) internal returns (bool) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;
        Validator memory validator = $._manager.getValidator(validationID);

        // Ensure the delegator is active
        if (delegator.status != DelegatorStatus.Active) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        // Only the delegation owner or parent validator can end the delegation.
        if (delegator.owner != _msgSender()) {
            // Validators can only remove delegations after the minimum stake duration has passed.
            if ($._posValidatorInfo[validationID].owner != _msgSender()) {
                revert UnauthorizedOwner(_msgSender());
            }

            if (
                block.timestamp <
                validator.startTime +
                    $._posValidatorInfo[validationID].minStakeDuration
            ) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }
        }

        address rewardRecipient = _getDelegatorRewardRecipient(delegationID);
        if (validator.status == ValidatorStatus.Active) {
            // Check that minimum stake duration has passed.
            if (
                block.timestamp < delegator.startTime + $._minimumStakeDuration
            ) {
                revert MinStakeDurationNotPassed(uint64(block.timestamp));
            }

            if (includeUptimeProof) {
                // Uptime proofs include the absolute number of seconds the validator has been active.
                _updateUptime(validationID, messageIndex);
            }

            // Set the delegator status to pending removed, so that it can be properly removed in
            // the complete step, even if the delivered nonce is greater than the nonce used to
            // initiate the removal.
            $._delegatorStakes[delegationID].status = DelegatorStatus
                .PendingRemoved;

            ($._delegatorStakes[delegationID].endingNonce, ) = $
                ._manager
                .initiateValidatorWeightUpdate(
                    validationID,
                    validator.weight - delegator.weight
                );

            uint256 reward = _calculateAndSetDelegationReward(
                delegator,
                rewardRecipient,
                delegationID
            );

            emit InitiatedDelegatorRemoval({
                delegationID: delegationID,
                validationID: validationID
            });
            return (reward > 0);
        } else if (validator.status == ValidatorStatus.Completed) {
            _calculateAndSetDelegationReward(
                delegator,
                rewardRecipient,
                delegationID
            );
            _completeDelegatorRemoval(delegationID);
            // If the validator has completed, then no further uptimes may be submitted, so we always
            // end the delegation.
            return true;
        } else {
            revert InvalidValidatorStatus(validator.status);
        }
    }

    /**
     * @dev Calculates the reward owed to the delegator based on the state of the delegator and its corresponding validator.
     * then set the reward and reward recipient in the storage.
     */
    function _calculateAndSetDelegationReward(
        Delegator memory delegator,
        address rewardRecipient,
        bytes32 delegationID
    ) private returns (uint256) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Validator memory validator = $._manager.getValidator(
            delegator.validationID
        );

        uint64 delegationEndTime;
        if (
            validator.status == ValidatorStatus.PendingRemoved ||
            validator.status == ValidatorStatus.Completed
        ) {
            delegationEndTime = validator.endTime;
        } else if (validator.status == ValidatorStatus.Active) {
            delegationEndTime = uint64(block.timestamp);
        } else {
            // Should be unreachable.
            revert InvalidValidatorStatus(validator.status);
        }

        // Only give rewards in the case that the delegation started before the validator exited.
        if (delegationEndTime <= delegator.startTime) {
            return 0;
        }

        // Calculate remaining reward from last claim (or start) to end
        uint64 lastClaimTime = delegator.lastRewardClaimTime;
        uint64 lastClaimUptime = delegator.lastClaimUptimeSeconds;

        // If never claimed before, use delegator start time
        // Note: lastClaimUptimeSeconds is initialized in completeDelegatorRegistration
        // to the validator's uptime at registration time, so we keep that value
        if (lastClaimTime == 0) {
            lastClaimTime = delegator.startTime;
        }

        uint64 currentUptime = $
            ._posValidatorInfo[delegator.validationID]
            .uptimeSeconds;

        uint256 reward = $._rewardCalculator.calculateIncrementalReward({
            stakeAmount: weightToValue(delegator.weight),
            lastClaimTime: lastClaimTime,
            currentTime: delegationEndTime,
            lastClaimUptimeSeconds: lastClaimUptime,
            currentUptimeSeconds: currentUptime,
            validatorStartTime: validator.startTime
        });

        if (rewardRecipient == address(0)) {
            rewardRecipient = delegator.owner;
        }

        $._redeemableDelegatorRewards[delegationID] = reward;
        $._delegatorRewardRecipients[delegationID] = rewardRecipient;

        return reward;
    }

    /**
     * @notice See {IStakingManager-resendUpdateDelegator}.
     * @dev Resending the latest validator weight with the latest nonce is safe because all weight changes are
     * cumulative, so the latest weight change will always include the weight change for any added delegators.
     */
    function resendUpdateDelegator(bytes32 delegationID) external {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];
        if (
            delegator.status != DelegatorStatus.PendingAdded &&
            delegator.status != DelegatorStatus.PendingRemoved
        ) {
            revert InvalidDelegatorStatus(delegator.status);
        }

        Validator memory validator = $._manager.getValidator(
            delegator.validationID
        );
        if (validator.sentNonce == 0) {
            // Should be unreachable.
            revert InvalidDelegationID(delegationID);
        }

        // Submit the message to the Warp precompile.
        WARP_MESSENGER.sendWarpMessage(
            ValidatorMessages.packL1ValidatorWeightMessage(
                delegator.validationID,
                validator.sentNonce,
                validator.weight
            )
        );
    }

    /**
     * @notice See {IStakingManager-completeDelegatorRemoval}.
     * Extends the functionality of {ACP99Manager-completeValidatorWeightUpdate} by updating the delegation status and unlocking delegation rewards.
     */
    function completeDelegatorRemoval(
        bytes32 delegationID,
        uint32 messageIndex
    ) external nonReentrant {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        Delegator memory delegator = $._delegatorStakes[delegationID];

        // Ensure the delegator is pending removed. Since anybody can call this function once
        // end delegation has been initiated, we need to make sure that this function is only
        // callable after that has been done.
        if (delegator.status != DelegatorStatus.PendingRemoved) {
            revert InvalidDelegatorStatus(delegator.status);
        }
        Validator memory validator = $._manager.getValidator(
            delegator.validationID
        );

        // We only expect an ICM message if we haven't received a weight update with a nonce greater than the delegation's ending nonce
        if (
            $._manager.getValidator(delegator.validationID).status !=
            ValidatorStatus.Completed &&
            validator.receivedNonce < delegator.endingNonce
        ) {
            (bytes32 validationID, uint64 nonce) = $
                ._manager
                .completeValidatorWeightUpdate(messageIndex);
            if (delegator.validationID != validationID) {
                revert UnexpectedValidationID(
                    validationID,
                    delegator.validationID
                );
            }

            // The received nonce should be at least as high as the delegation's ending nonce. This allows a weight
            // update using a higher nonce (which implicitly includes the delegation's weight update) to be used to
            // complete delisting for an earlier delegation. This is necessary because the P-Chain is only willing
            // to sign the latest weight update.
            if (delegator.endingNonce > nonce) {
                revert InvalidNonce(nonce);
            }
        }

        _completeDelegatorRemoval(delegationID);
    }

    function _completeDelegatorRemoval(bytes32 delegationID) internal {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        Delegator memory delegator = $._delegatorStakes[delegationID];
        bytes32 validationID = delegator.validationID;

        // To prevent churn tracker abuse, check that one full churn period has passed,
        // so a delegator may not stake twice in the same churn period.
        if (
            block.timestamp <
            delegator.startTime + $._manager.getChurnPeriodSeconds()
        ) {
            revert MinStakeDurationNotPassed(uint64(block.timestamp));
        }

        address rewardRecipient = _getDelegatorRewardRecipient(delegationID);
        // Store the recipient for later claiming if needed (in case reward distribution fails)
        if ($._delegatorRewardRecipients[delegationID] == address(0)) {
            $._delegatorRewardRecipients[delegationID] = rewardRecipient;
        }

        (
            uint256 delegationRewards,
            uint256 validatorFees
        ) = _withdrawDelegationRewards(
                rewardRecipient,
                delegationID,
                validationID
            );

        // If rewards were successfully distributed, delete all delegator data
        // If distribution failed, preserve necessary data for later claiming via claimDelegatorRewards:
        // - Set status to Unknown (indicates completed but with pending rewards)
        // - Keep validationID and owner for permission checks and commission calculation
        // This is consistent with how validator data is handled (preserving info for later claiming)
        if (
            delegationRewards > 0 ||
            $._redeemableDelegatorRewards[delegationID] == 0
        ) {
            // Success: clean up all data
            delete $._delegatorStakes[delegationID];
        } else {
            // Failed: preserve essential data, mark as completed
            $._delegatorStakes[delegationID].status = DelegatorStatus.Unknown;
            // Keep: validationID, owner (for permission check in claimDelegatorRewards)
            // Clear unnecessary fields to save gas
            $._delegatorStakes[delegationID].weight = 0;
            $._delegatorStakes[delegationID].startTime = 0;
            $._delegatorStakes[delegationID].startingNonce = 0;
            $._delegatorStakes[delegationID].endingNonce = 0;
            $._delegatorStakes[delegationID].lastRewardClaimTime = 0;
            $._delegatorStakes[delegationID].lastClaimUptimeSeconds = 0;
        }

        // Unlock the delegator's stake.
        uint256 stakeAmount = weightToValue(delegator.weight);
        _unlock(delegator.owner, stakeAmount);

        emit CompletedDelegatorRemoval(
            delegationID,
            validationID,
            stakeAmount,
            delegationRewards,
            validatorFees
        );
    }

    /**
     * @dev This function must be implemented to mint rewards to validators and delegators.
     * @return success True if reward was successfully distributed, false otherwise.
     * @notice Implementations should NOT revert on failure. Instead, return false to allow
     * stake unlocking to proceed while preserving rewards for later claiming.
     */
    function _reward(
        address account,
        uint256 amount
    ) internal virtual returns (bool success);

    /**
     * @dev Return true if this is a PoS validator with locked stake. Returns false if this was originally a PoA
     * validator that was later migrated to this PoS manager, or the validator was part of the initial validator set.
     */
    function _isPoSValidator(
        bytes32 validationID
    ) internal view returns (bool) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        return $._posValidatorInfo[validationID].owner != address(0);
    }

    function _withdrawValidationRewards(
        address rewardRecipient,
        bytes32 validationID
    ) internal {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        uint256 rewards = $._redeemableValidatorRewards[validationID];
        if (rewards == 0) {
            return;
        }

        bool success = _reward(rewardRecipient, rewards);

        // Only clear rewards if distribution succeeded
        // If failed, rewards remain claimable via claimValidatorRewards
        if (success) {
            delete $._redeemableValidatorRewards[validationID];
            emit ValidatorRewardClaimed(validationID, rewardRecipient, rewards);
        }
    }

    /**
     * @dev Withdraws pending delegation rewards to the recipient and allocates validator fees.
     *
     * This function handles the distribution of stored gross rewards (from $._redeemableDelegatorRewards):
     * 1. Calculates validator commission (fees) based on validator's delegationFeeBips
     * 2. Distributes net rewards (gross - fees) to the delegator's reward recipient
     * 3. Allocates commission to the validator's redeemable rewards
     *
     * @param rewardRecipient The address to receive the delegation rewards
     * @param delegationID The ID of the delegation
     * @param validationID The ID of the validation (used to get delegationFeeBips and allocate fees)
     * @return delegationRewards The amount of rewards distributed to the delegator (0 if failed)
     * @return validatorFees The amount of fees allocated to the validator (0 if failed)
     */
    function _withdrawDelegationRewards(
        address rewardRecipient,
        bytes32 delegationID,
        bytes32 validationID
    ) internal returns (uint256, uint256) {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        uint256 delegationRewards;
        uint256 validatorFees;

        uint256 rewards = $._redeemableDelegatorRewards[delegationID];

        if (rewards > 0) {
            validatorFees =
                (rewards *
                    $._posValidatorInfo[validationID].delegationFeeBips) /
                BIPS_CONVERSION_FACTOR;

            // Reward the remaining tokens to the delegator.
            delegationRewards = rewards - validatorFees;
            bool success = _reward(rewardRecipient, delegationRewards);

            // Only clear rewards and allocate validator fees if distribution succeeded
            // If failed, rewards remain claimable via claimDelegatorRewards
            if (success) {
                delete $._redeemableDelegatorRewards[delegationID];
                delete $._delegatorRewardRecipients[delegationID];

                // Allocate the delegation fees to the validator.
                if (validatorFees > 0) {
                    $._redeemableValidatorRewards[
                        validationID
                    ] += validatorFees;
                    emit DelegationFeesAccrued(
                        validationID,
                        delegationID,
                        validatorFees
                    );
                }

                emit DelegatorRewardClaimed(
                    delegationID,
                    rewardRecipient,
                    delegationRewards
                );
            } else {
                // Reset values since distribution failed
                delegationRewards = 0;
                validatorFees = 0;
            }
        } else {
            // No rewards to distribute, clean up rewardRecipient
            delete $._delegatorRewardRecipients[delegationID];
        }

        return (delegationRewards, validatorFees);
    }

    // ============================================
    // Internal Configuration Functions
    // ============================================

    /**
     * @notice Internal function to update the staking configuration parameters
     * @dev Child contracts should call this with appropriate access control
     *
     * IMPORTANT: Parameter modification impact analysis:
     *
     * 1. minimumStakeAmount / maximumStakeAmount:
     *    - Only affects NEW validator registrations
     *    - Existing validators are NOT affected
     *
     * 2. minimumDelegationFeeBips:
     *    - Only affects NEW validator registrations
     *    - Existing validators keep their original delegationFeeBips setting
     *
     * 3. maximumStakeMultiplier:
     *    - Only affects NEW delegator registrations
     *    - If reduced: existing validators with total weight > startingWeight * newMultiplier
     *      will NOT be able to accept new delegations, but existing delegations remain valid
     *    - Existing delegations are NOT affected
     *
     * 4. minimumStakeDuration:
     *    - For Validators: Only affects NEW registrations (validators store their own minStakeDuration at registration)
     *    - For Delegators: AFFECTS EXISTING delegators. Delegator exit uses this global value.
     *      * Increasing: existing delegators must wait longer to exit (use with caution)
     *      * Decreasing: existing delegators can exit earlier
     *    - Note: Validator-forced delegator removal uses validator's stored minStakeDuration, not this global value
     */
    function _updateStakingConfig(
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint64 minimumStakeDuration,
        uint16 minimumDelegationFeeBips,
        uint8 maximumStakeMultiplier
    ) internal {
        StakingManagerStorage storage $ = _getStakingManagerStorage();

        // Validate parameters
        if (
            minimumDelegationFeeBips == 0 ||
            minimumDelegationFeeBips > MAXIMUM_DELEGATION_FEE_BIPS
        ) {
            revert InvalidDelegationFee(minimumDelegationFeeBips);
        }
        if (minimumStakeAmount > maximumStakeAmount) {
            revert InvalidStakeAmount(minimumStakeAmount);
        }
        if (
            maximumStakeMultiplier == 0 ||
            maximumStakeMultiplier > MAXIMUM_STAKE_MULTIPLIER_LIMIT
        ) {
            revert InvalidStakeMultiplier(maximumStakeMultiplier);
        }
        if (minimumStakeDuration < $._manager.getChurnPeriodSeconds()) {
            revert InvalidMinStakeDuration(minimumStakeDuration);
        }

        // Update storage
        $._minimumStakeAmount = minimumStakeAmount;
        $._maximumStakeAmount = maximumStakeAmount;
        $._minimumStakeDuration = minimumStakeDuration;
        $._minimumDelegationFeeBips = minimumDelegationFeeBips;
        $._maximumStakeMultiplier = maximumStakeMultiplier;
    }

    /**
     * @notice Internal function to update the reward calculator
     * @dev Child contracts should call this with appropriate access control
     */
    function _updateRewardCalculator(
        IRewardCalculator newRewardCalculator
    ) internal {
        if (address(newRewardCalculator) == address(0)) {
            revert ZeroAddress();
        }
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        $._rewardCalculator = newRewardCalculator;
    }

    /**
     * @notice Internal function to get the staking configuration
     */
    function _getStakingConfig()
        internal
        view
        returns (
            uint256 minimumStakeAmount,
            uint256 maximumStakeAmount,
            uint64 minimumStakeDuration,
            uint16 minimumDelegationFeeBips,
            uint8 maximumStakeMultiplier,
            uint256 weightToValueFactor
        )
    {
        StakingManagerStorage storage $ = _getStakingManagerStorage();
        return (
            $._minimumStakeAmount,
            $._maximumStakeAmount,
            $._minimumStakeDuration,
            $._minimumDelegationFeeBips,
            uint8($._maximumStakeMultiplier),
            $._weightToValueFactor
        );
    }

    /**
     * @notice Internal function to get the reward calculator address
     */
    function _getRewardCalculator() internal view returns (address) {
        return address(_getStakingManagerStorage()._rewardCalculator);
    }
}

// (c) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem
pragma solidity 0.8.25;

import {PChainOwner, ConversionData} from "./interfaces/IACP99Manager.sol";

/**
 * @dev Packing utilities for the ICM message types used by the Validator Manager contracts, as specified in ACP-77:
 * https://github.com/avalanche-foundation/ACPs/tree/main/ACPs/77-reinventing-subnets
 */
