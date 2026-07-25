contract KiteStakingManager is
    Initializable,
    StakingManager,
    Ownable2StepUpgradeable,
    IKiteStakingManager
{
    using Address for address payable;

    /// @custom:storage-location erc7201:avalanche-icm.storage.KiteStakingManager
    struct KiteStakingManagerStorage {
        /// @notice The reward vault address
        RewardVault rewardVault;
    }

    // keccak256(abi.encode(uint256(keccak256("avalanche-icm.storage.KiteStakingManager")) - 1)) & ~bytes32(uint256(0xff));
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 public constant KITE_STAKING_MANAGER_STORAGE_LOCATION =
        0x6b1e6c6e0b6e6f6e6c6f6e6b6e6f6e6c6b6e6f6e6c6f6e6b6e6f6e6c6b6e6f00;

    /// @notice Error thrown when reward vault address is invalid (zero address)
    error InvalidRewardVaultAddress();

    /// @notice Emitted when staking configuration is updated
    event StakingConfigUpdated(
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint64 minimumStakeDuration,
        uint16 minimumDelegationFeeBips,
        uint8 maximumStakeMultiplier
    );

    /// @notice Emitted when the reward calculator is updated
    event RewardCalculatorUpdated(
        address indexed oldCalculator,
        address indexed newCalculator
    );

    /// @notice Emitted when the reward vault is updated
    event RewardVaultUpdated(
        address indexed oldVault,
        address indexed newVault
    );

    /// @notice Emitted when reward distribution fails (e.g., insufficient vault balance)
    /// @dev Rewards remain claimable via claimValidatorRewards/claimDelegatorRewards
    event RewardDistributionFailed(
        address indexed recipient,
        uint256 amount,
        string reason
    );

    function _getKiteStakingManagerStorage()
        private
        pure
        returns (KiteStakingManagerStorage storage $)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            $.slot := KITE_STAKING_MANAGER_STORAGE_LOCATION
        }
    }

    constructor(ICMInitializable init) {
        if (init == ICMInitializable.Disallowed) {
            _disableInitializers();
        }
    }

    /**
     * @notice Initialize the Kite staking manager
     * @param settings Initial settings for the PoS validator manager
     * @param admin The address of the admin who can update configuration
     * @param rewardVault The address of the reward vault
     */
    // solhint-disable ordering
    function initialize(
        StakingManagerSettings calldata settings,
        address admin,
        address rewardVault
    ) external initializer {
        __KiteStakingManager_init(settings, admin, rewardVault);
    }

    // solhint-disable-next-line func-name-mixedcase
    function __KiteStakingManager_init(
        StakingManagerSettings calldata settings,
        address admin,
        address rewardVault
    ) internal onlyInitializing {
        __StakingManager_init(settings);
        __Ownable_init(admin);
        __KiteStakingManager_init_unchained(rewardVault);
    }

    // solhint-disable-next-line func-name-mixedcase
    function __KiteStakingManager_init_unchained(
        address rewardVault
    ) internal onlyInitializing {
        if (rewardVault == address(0)) {
            revert InvalidRewardVaultAddress();
        }
        KiteStakingManagerStorage storage $ = _getKiteStakingManagerStorage();
        $.rewardVault = RewardVault(payable(rewardVault));
    }

    /**
     * @notice Returns the reward vault address
     * @return The reward vault contract
     */
    function getRewardVault() external view returns (address) {
        return address(_getKiteStakingManagerStorage().rewardVault);
    }

    /**
     * @notice See {IKiteStakingManager-initiateValidatorRegistration}.
     */
    function initiateValidatorRegistration(
        bytes memory nodeID,
        bytes memory blsPublicKey,
        PChainOwner memory remainingBalanceOwner,
        PChainOwner memory disableOwner,
        uint16 delegationFeeBips,
        uint64 minStakeDuration,
        address rewardRecipient
    ) external payable nonReentrant returns (bytes32) {
        return
            _initiateValidatorRegistration({
                nodeID: nodeID,
                blsPublicKey: blsPublicKey,
                remainingBalanceOwner: remainingBalanceOwner,
                disableOwner: disableOwner,
                delegationFeeBips: delegationFeeBips,
                minStakeDuration: minStakeDuration,
                stakeAmount: msg.value,
                rewardRecipient: rewardRecipient
            });
    }

    /**
     * @notice See {IKiteStakingManager-initiateDelegatorRegistration}.
     */
    function initiateDelegatorRegistration(
        bytes32 validationID,
        address rewardRecipient
    ) external payable nonReentrant returns (bytes32) {
        return
            _initiateDelegatorRegistration(
                validationID,
                _msgSender(),
                msg.value,
                rewardRecipient
            );
    }

    /**
     * @notice See {StakingManager-_lock}
     * @dev For native tokens, the value is already transferred with the transaction
     */
    function _lock(uint256 value) internal virtual override returns (uint256) {
        return value;
    }

    /**
     * @notice See {StakingManager-_unlock}
     * @dev Transfers native tokens back to the staker
     */
    function _unlock(address to, uint256 value) internal virtual override {
        payable(to).sendValue(value);
    }

    /**
     * @notice See {StakingManager-_reward}
     * @dev Distributes rewards from the RewardVault instead of minting.
     * Returns false instead of reverting if distribution fails, allowing stake
     * unlocking to proceed while preserving rewards for later claiming.
     */
    function _reward(
        address account,
        uint256 amount
    ) internal virtual override returns (bool) {
        if (amount == 0) {
            return true;
        }

        KiteStakingManagerStorage storage $ = _getKiteStakingManagerStorage();
        RewardVault vault = $.rewardVault;

        if (address(vault) == address(0)) {
            emit RewardDistributionFailed(
                account,
                amount,
                "RewardVault not set"
            );
            return false;
        }

        uint256 vaultBalance = address(vault).balance;
        if (vaultBalance < amount) {
            emit RewardDistributionFailed(
                account,
                amount,
                "Insufficient vault balance"
            );
            return false;
        }

        vault.distributeReward(account, amount);
        return true;
    }

    // ============================================
    // Admin Configuration Functions
    // ============================================

    /**
     * @notice Updates the staking configuration parameters
     * @param minimumStakeAmount The new minimum stake amount
     * @param maximumStakeAmount The new maximum stake amount
     * @param minimumStakeDuration The new minimum stake duration
     * @param minimumDelegationFeeBips The new minimum delegation fee in basis points
     * @param maximumStakeMultiplier The new maximum stake multiplier
     */
    function updateStakingConfig(
        uint256 minimumStakeAmount,
        uint256 maximumStakeAmount,
        uint64 minimumStakeDuration,
        uint16 minimumDelegationFeeBips,
        uint8 maximumStakeMultiplier
    ) external onlyOwner {
        _updateStakingConfig(
            minimumStakeAmount,
            maximumStakeAmount,
            minimumStakeDuration,
            minimumDelegationFeeBips,
            maximumStakeMultiplier
        );
        emit StakingConfigUpdated(
            minimumStakeAmount,
            maximumStakeAmount,
            minimumStakeDuration,
            minimumDelegationFeeBips,
            maximumStakeMultiplier
        );
    }

    /**
     * @notice Updates the reward calculator
     * @param newRewardCalculator The address of the new reward calculator
     */
    function updateRewardCalculator(
        IRewardCalculator newRewardCalculator
    ) external onlyOwner {
        address oldCalculator = _getRewardCalculator();
        _updateRewardCalculator(newRewardCalculator);
        emit RewardCalculatorUpdated(
            oldCalculator,
            address(newRewardCalculator)
        );
    }

    /**
     * @notice Updates the reward vault address
     * @param newRewardVault The address of the new reward vault
     */
    function updateRewardVault(address newRewardVault) external onlyOwner {
        if (newRewardVault == address(0)) {
            revert InvalidRewardVaultAddress();
        }
        KiteStakingManagerStorage storage $ = _getKiteStakingManagerStorage();
        address oldVault = address($.rewardVault);
        $.rewardVault = RewardVault(payable(newRewardVault));
        emit RewardVaultUpdated(oldVault, newRewardVault);
    }

    // ============================================
    // Configuration Getters
    // ============================================

    /**
     * @notice Returns the current staking configuration
     */
    function getStakingConfig()
        external
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
        return _getStakingConfig();
    }

    /**
     * @notice Returns the current reward calculator address
     */
    function getRewardCalculator() external view returns (address) {
        return _getRewardCalculator();
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable2Step.sol)

pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "./OwnableUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is specified at deployment time in the constructor for `Ownable`. This
 * can later be changed with {transferOwnership} and {acceptOwnership}.
 *
 * This module is used through inheritance. It will make available all functions
 * from parent (Ownable).
 */
