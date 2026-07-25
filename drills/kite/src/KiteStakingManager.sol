// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {StakingManager} from "./StakingManager.sol";
import {StakingManagerSettings, IRewardCalculator} from "./interfaces/IStakingManager.sol";
import {PChainOwner} from "./ACP99Manager.sol";
import {IKiteStakingManager} from "./interfaces/IKiteStakingManager.sol";
import {RewardVault} from "./RewardVault.sol";
import {ICMInitializable} from "./ICMInitializable.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@5.0.2/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/access/Ownable2StepUpgradeable.sol";

/**
 * @title KiteStakingManager
 * @notice Implementation of staking manager for Kite network using native tokens.
 */
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
abstract contract Ownable2StepUpgradeable is Initializable, OwnableUpgradeable {
    /// @custom:storage-location erc7201:openzeppelin.storage.Ownable2Step
    struct Ownable2StepStorage {
        address _pendingOwner;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Ownable2Step")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant Ownable2StepStorageLocation = 0x237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00;

    function _getOwnable2StepStorage() private pure returns (Ownable2StepStorage storage $) {
        assembly {
            $.slot := Ownable2StepStorageLocation
        }
    }

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    function __Ownable2Step_init() internal onlyInitializing {
    }

    function __Ownable2Step_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        Ownable2StepStorage storage $ = _getOwnable2StepStorage();
        return $._pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        Ownable2StepStorage storage $ = _getOwnable2StepStorage();
        $._pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        Ownable2StepStorage storage $ = _getOwnable2StepStorage();
        delete $._pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() public virtual {
        address sender = _msgSender();
        if (pendingOwner() != sender) {
            revert OwnableUnauthorizedAccount(sender);
        }
        _transferOwnership(sender);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;

import {ContextUpgradeable} from "../utils/ContextUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    /// @custom:storage-location erc7201:openzeppelin.storage.Ownable
    struct OwnableStorage {
        address _owner;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Ownable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    function __Ownable_init(address initialOwner) internal onlyInitializing {
        __Ownable_init_unchained(initialOwner);
    }

    function __Ownable_init_unchained(address initialOwner) internal onlyInitializing {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        address oldOwner = $._owner;
        $._owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.20;

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/ReentrancyGuard.sol)

pragma solidity ^0.8.20;
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyGuardStorage {
        uint256 _status;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ReentrancyGuardStorageLocation = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _getReentrancyGuardStorage() private pure returns (ReentrancyGuardStorage storage $) {
        assembly {
            $.slot := ReentrancyGuardStorageLocation
        }
    }

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if ($._status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        $._status = ENTERED;
    }

    function _nonReentrantAfter() private {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        $._status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        ReentrancyGuardStorage storage $ = _getReentrancyGuardStorage();
        return $._status == ENTERED;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity 0.8.25;

struct WarpMessage {
    bytes32 sourceChainID;
    address originSenderAddress;
    bytes payload;
}

struct WarpBlockHash {
    bytes32 sourceChainID;
    bytes32 blockHash;
}

interface IWarpMessenger {
    event SendWarpMessage(
        address indexed sender,
        bytes32 indexed messageID,
        bytes message
    );

    // sendWarpMessage emits a request for the subnet to send a warp message from [msg.sender]
    // with the specified parameters.
    // This emits a SendWarpMessage log from the precompile. When the corresponding block is accepted
    // the Accept hook of the Warp precompile is invoked with all accepted logs emitted by the Warp
    // precompile.
    // Each validator then adds the UnsignedWarpMessage encoded in the log to the set of messages
    // it is willing to sign for an off-chain relayer to aggregate Warp signatures.
    function sendWarpMessage(
        bytes calldata payload
    ) external returns (bytes32 messageID);

    // getVerifiedWarpMessage parses the pre-verified warp message in the
    // predicate storage slots as a WarpMessage and returns it to the caller.
    // If the message exists and passes verification, returns the verified message
    // and true.
    // Otherwise, returns false and the empty value for the message.
    function getVerifiedWarpMessage(
        uint32 index
    ) external view returns (WarpMessage calldata message, bool valid);

    // getVerifiedWarpBlockHash parses the pre-verified WarpBlockHash message in the
    // predicate storage slots as a WarpBlockHash message and returns it to the caller.
    // If the message exists and passes verification, returns the verified message
    // and true.
    // Otherwise, returns false and the empty value for the message.
    function getVerifiedWarpBlockHash(
        uint32 index
    ) external view returns (WarpBlockHash calldata warpBlockHash, bool valid);

    // getBlockchainID returns the snow.Context BlockchainID of this chain.
    // This blockchainID is the hash of the transaction that created this blockchain on the P-Chain
    // and is not related to the Ethereum ChainID.
    function getBlockchainID() external view returns (bytes32 blockchainID);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;

import {Context} from "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialOwner) {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable2Step.sol)

pragma solidity ^0.8.20;

import {Ownable} from "./Ownable.sol";

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
abstract contract Ownable2Step is Ownable {
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        return _pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        delete _pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() public virtual {
        address sender = _msgSender();
        if (pendingOwner() != sender) {
            revert OwnableUnauthorizedAccount(sender);
        }
        _transferOwnership(sender);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * ==== Security Considerations
 *
 * There are two important considerations concerning the use of `permit`. The first is that a valid permit signature
 * expresses an allowance, and it should not be assumed to convey additional meaning. In particular, it should not be
 * considered as an intention to spend the allowance in any specific way. The second is that because permits have
 * built-in replay protection and can be submitted by anyone, they can be frontrun. A protocol that uses permits should
 * take this into consideration and allow a `permit` call to fail. Combining these two aspects, a pattern that may be
 * generally recommended is:
 *
 * ```solidity
 * function doThingWithPermit(..., uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public {
 *     try token.permit(msg.sender, address(this), value, deadline, v, r, s) {} catch {}
 *     doThing(..., value);
 * }
 *
 * function doThing(..., uint256 value) public {
 *     token.safeTransferFrom(msg.sender, address(this), value);
 *     ...
 * }
 * ```
 *
 * Observe that: 1) `msg.sender` is used as the owner, leaving no ambiguity as to the signer intent, and 2) the use of
 * `try/catch` allows the permit to fail and makes the code tolerant to frontrunning. (See also
 * {SafeERC20-safeTransferFrom}).
 *
 * Additionally, note that smart contract wallets (such as Argent or Safe) are not able to produce permit signatures, so
 * contracts should have entry points that don't rely on permit.
 */
interface IERC20Permit {
    /**
     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,
     * given ``owner``'s signed approval.
     *
     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
     * ordering also apply here.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     *
     * For more information on the signature format, see the
     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
     * section].
     *
     * CAUTION: See Security Considerations above.
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;

import {IERC20} from "../IERC20.sol";
import {IERC20Permit} from "../extensions/IERC20Permit.sol";
import {Address} from "../../../utils/Address.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    /**
     * @dev An operation with an ERC20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address-functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silents catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return success && (returndata.length == 0 || abi.decode(returndata, (bool))) && address(token).code.length > 0;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/Address.sol)

pragma solidity ^0.8.20;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error AddressInsufficientBalance(address account);

    /**
     * @dev There's no code at `target` (it is not a contract).
     */
    error AddressEmptyCode(address target);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedInnerCall();

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.20/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert AddressInsufficientBalance(address(this));
        }

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert FailedInnerCall();
        }
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason or custom error, it is bubbled
     * up by this function (like regular Solidity function calls). However, if
     * the call reverted with no returned reason, this function reverts with a
     * {FailedInnerCall} error.
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and reverts if the target
     * was not a contract or bubbling up the revert reason (falling back to {FailedInnerCall}) in case of an
     * unsuccessful call.
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and reverts if it wasn't, either by bubbling the
     * revert reason or with a default {FailedInnerCall} error.
     */
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    /**
     * @dev Reverts with returndata if present. Otherwise reverts with {FailedInnerCall}.
     */
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedInnerCall();
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
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

// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem
pragma solidity 0.8.25;

enum ICMInitializable {
    Allowed,
    Disallowed
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts@5.0.2/access/Ownable2Step.sol";
import {Address} from "@openzeppelin/contracts@5.0.2/utils/Address.sol";
import {IERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts@5.0.2/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RewardVault
 * @notice A vault contract that holds native tokens (Kite) for staking rewards distribution.
 */
contract RewardVault is Ownable2Step {
    using Address for address payable;
    using SafeERC20 for IERC20;

    /// @notice The address of the staking manager that can distribute rewards
    address public stakingManager;

    /// @notice Emitted when native tokens are deposited
    event Deposited(address indexed sender, uint256 amount);

    /// @notice Emitted when owner withdraws native tokens
    event Withdrawn(address indexed to, uint256 amount);

    /// @notice Emitted when rewards are distributed by the staking manager
    event RewardDistributed(address indexed to, uint256 amount);

    /// @notice Emitted when the staking manager address is updated
    event StakingManagerUpdated(
        address indexed oldManager,
        address indexed newManager
    );

    /// @notice Emitted when ERC20 tokens are rescued
    event ERC20Rescued(
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /// @notice Error thrown when caller is not the staking manager
    error UnauthorizedCaller(address caller);

    /// @notice Error thrown when trying to set zero address
    error ZeroAddress();

    /// @notice Error thrown when trying to withdraw more than balance
    error InsufficientBalance(uint256 requested, uint256 available);

    /// @notice Error thrown when transfer fails
    error TransferFailed();

    /**
     * @notice Constructs the RewardVault contract
     * @param initialOwner The initial owner of the vault
     */
    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @notice Allows anyone to deposit native tokens into the vault
     */
    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Allows anyone to deposit native tokens into the vault
     */
    function deposit() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Sets the staking manager address
     * @param newStakingManager The address of the staking manager
     */
    function setStakingManager(address newStakingManager) external onlyOwner {
        if (newStakingManager == address(0)) {
            revert ZeroAddress();
        }
        address oldManager = stakingManager;
        stakingManager = newStakingManager;
        emit StakingManagerUpdated(oldManager, newStakingManager);
    }

    /**
     * @notice Allows owner to withdraw native tokens from the vault
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to withdraw
     */
    function withdraw(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) {
            revert ZeroAddress();
        }
        if (amount > address(this).balance) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        payable(to).sendValue(amount);
        emit Withdrawn(to, amount);
    }

    /**
     * @notice Allows the staking manager to distribute rewards
     * @param to The address to send the rewards to
     * @param amount The amount of rewards to distribute
     */
    function distributeReward(address to, uint256 amount) external {
        if (msg.sender != stakingManager) {
            revert UnauthorizedCaller(msg.sender);
        }
        if (to == address(0)) {
            revert ZeroAddress();
        }
        if (amount > address(this).balance) {
            revert InsufficientBalance(amount, address(this).balance);
        }
        payable(to).sendValue(amount);
        emit RewardDistributed(to, amount);
    }

    /**
     * @notice Allows owner to rescue ERC20 tokens that were accidentally sent to the vault
     * @param token The address of the ERC20 token to rescue
     * @param to The address to send the tokens to
     * @param amount The amount of tokens to rescue
     */
    function rescueERC20(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner {
        if (token == address(0)) {
            revert ZeroAddress();
        }
        if (to == address(0)) {
            revert ZeroAddress();
        }
        IERC20(token).safeTransfer(to, amount);
        emit ERC20Rescued(token, to, amount);
    }

    /**
     * @notice Returns the current balance of the vault
     * @return The balance in native tokens
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// SPDX-License-Identifier: LicenseRef-Ecosystem
// (c) 2024, Ava Labs, Inc. All rights reserved.

// modified from https://github.com/ava-labs/icm-contracts/blob/main/contracts/validator-manager/StakingManager.sol

pragma solidity 0.8.25;

import {ValidatorMessages} from "./ValidatorMessages.sol";
import {IValidatorManager} from "./interfaces/IValidatorManager.sol";
import {Delegator, DelegatorStatus, IStakingManager, PoSValidatorInfo, StakingManagerSettings} from "./interfaces/IStakingManager.sol";
import {Validator, ValidatorStatus, PChainOwner} from "./interfaces/IACP99Manager.sol";
import {IRewardCalculator} from "./interfaces/IRewardCalculator.sol";
import {IWarpMessenger, WarpMessage} from "./interfaces/IWarpMessenger.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/utils/ReentrancyGuardUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/utils/ContextUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable@5.0.2/access/OwnableUpgradeable.sol";

/**
 * @dev Implementation of the {IStakingManager} interface.
 */
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
library ValidatorMessages {
    // The information that uniquely identifies an L1 validation period.
    // The validationID is the SHA-256 hash of the concatenation of the CODEC_ID,
    // REGISTER_L1_VALIDATOR_MESSAGE_TYPE_ID, and the concatenated ValidationPeriod fields.
    struct ValidationPeriod {
        bytes32 subnetID;
        bytes nodeID;
        bytes blsPublicKey;
        uint64 registrationExpiry;
        PChainOwner remainingBalanceOwner;
        PChainOwner disableOwner;
        uint64 weight;
    }

    // The P-Chain uses a hardcoded codecID of 0 for all messages.
    uint16 internal constant CODEC_ID = 0;

    // The P-Chain signs a SubnetToL1ConversionMessage that is used to verify the L1's initial validators.
    uint32 internal constant SUBNET_TO_L1_CONVERSION_MESSAGE_TYPE_ID = 0;

    // L1s send a RegisterL1ValidatorMessage to the P-Chain to register a validator.
    uint32 internal constant REGISTER_L1_VALIDATOR_MESSAGE_TYPE_ID = 1;

    // The P-Chain responds with a RegisterL1ValidatorMessage indicating whether the registration was successful
    // for the given validation ID.
    uint32 internal constant L1_VALIDATOR_REGISTRATION_MESSAGE_TYPE_ID = 2;

    // L1s can send a L1ValidatorWeightMessage to the P-Chain to update a validator's weight.
    // The P-Chain responds with another L1ValidatorWeightMessage acknowledging the weight update.
    uint32 internal constant L1_VALIDATOR_WEIGHT_MESSAGE_TYPE_ID = 3;

    // The L1 will self-sign a ValidationUptimeMessage to be provided when a validator is initiating
    // the end of their validation period.
    uint32 internal constant VALIDATION_UPTIME_MESSAGE_TYPE_ID = 0;

    error InvalidMessageLength(uint32 actual, uint32 expected);
    error InvalidCodecID(uint32 id);
    error InvalidMessageType();
    error InvalidBLSPublicKey();

    /**
     * @notice Packs a SubnetToL1ConversionMessage message into a byte array.
     * The message format specification is:
     * +--------------------+----------+----------+
     * |            codecID :   uint16 |  2 bytes |
     * +--------------------+----------+----------+
     * |             typeID :   uint32 |  4 bytes |
     * +--------------------+----------+----------+
     * |       conversionID : [32]byte | 32 bytes |
     * +--------------------+----------+----------+
     *                                 | 38 bytes |
     *                                 +----------+
     *
     * @param conversionID The subnet conversion ID to pack into the message.
     * @return The packed message.
     */
    function packSubnetToL1ConversionMessage(
        bytes32 conversionID
    ) external pure returns (bytes memory) {
        return
            abi.encodePacked(
                CODEC_ID,
                SUBNET_TO_L1_CONVERSION_MESSAGE_TYPE_ID,
                conversionID
            );
    }

    /**
     * @notice Unpacks a byte array as a SubnetToL1ConversionMessage message.
     * The message format specification is the same as the one used in above for packing.
     *
     * @param input The byte array to unpack.
     * @return The unpacked conversionID.
     */
    function unpackSubnetToL1ConversionMessage(
        bytes memory input
    ) external pure returns (bytes32) {
        if (input.length != 38) {
            revert InvalidMessageLength(uint32(input.length), 38);
        }

        // Unpack the codec ID
        uint16 codecID;
        for (uint256 i; i < 2; ++i) {
            codecID |= uint16(uint8(input[i])) << uint16((8 * (1 - i)));
        }
        if (codecID != CODEC_ID) {
            revert InvalidCodecID(codecID);
        }

        // Unpack the type ID
        uint32 typeID;
        for (uint256 i; i < 4; ++i) {
            typeID |= uint32(uint8(input[i + 2])) << uint32((8 * (3 - i)));
        }
        if (typeID != SUBNET_TO_L1_CONVERSION_MESSAGE_TYPE_ID) {
            revert InvalidMessageType();
        }

        // Unpack the conversionID
        bytes32 conversionID;
        for (uint256 i; i < 32; ++i) {
            conversionID |= bytes32(
                uint256(uint8(input[i + 6])) << (8 * (31 - i))
            );
        }

        return conversionID;
    }

    /**
     * @notice Packs ConversionData into a byte array.
     * This byte array is the SHA256 pre-image of the conversionID hash
     * The message format specification is:
     *
     * ConversionData:
     * +----------------+-----------------+--------------------------------------------------------+
     * |       codecID  :          uint16 |                                                2 bytes |
     * +----------------+-----------------+--------------------------------------------------------+
     * |       subnetID :        [32]byte |                                               32 bytes |
     * +----------------+-----------------+--------------------------------------------------------+
     * | managerChainID :        [32]byte |                                               32 bytes |
     * +----------------+-----------------+--------------------------------------------------------+
     * | managerAddress :          []byte |                          4 + len(managerAddress) bytes |
     * +----------------+-----------------+--------------------------------------------------------+
     * |     validators : []ValidatorData |                        4 + sum(validatorLengths) bytes |
     * +----------------+-----------------+--------------------------------------------------------+
     *                                    | 74 + len(managerAddress) + len(validatorLengths) bytes |
     *                                    +--------------------------------------------------------+
     * ValidatorData:
     * +--------------+----------+------------------------+
     * |       nodeID :   []byte |  4 + len(nodeID) bytes |
     * +--------------+----------+------------------------+
     * | blsPublicKey : [48]byte |               48 bytes |
     * +--------------+----------+------------------------+
     * |       weight :   uint64 |                8 bytes |
     * +--------------+----------+------------------------+
     *                           | 60 + len(nodeID) bytes |
     *                           +------------------------+
     *
     * @dev Input validation is skipped, since the returned value is intended to be compared
     * directly with an authenticated ICM message.
     * @param conversionData The struct representing data to pack into the message.
     * @return The packed message.
     */
    function packConversionData(
        ConversionData memory conversionData
    ) external pure returns (bytes memory) {
        // Hardcoded 20 is for length of the managerAddress on EVM chains
        // solhint-disable-next-line func-named-parameters
        bytes memory res = abi.encodePacked(
            CODEC_ID,
            conversionData.subnetID,
            conversionData.validatorManagerBlockchainID,
            uint32(20),
            conversionData.validatorManagerAddress,
            uint32(conversionData.initialValidators.length)
        );
        // The approach below of encoding initialValidators using `abi.encodePacked` in a loop
        // was tested against pre-allocating the array and doing manual byte by byte packing and
        // it was found to be more gas efficient.
        for (uint256 i; i < conversionData.initialValidators.length; ++i) {
            res = abi.encodePacked(
                res,
                uint32(conversionData.initialValidators[i].nodeID.length),
                conversionData.initialValidators[i].nodeID,
                conversionData.initialValidators[i].blsPublicKey,
                conversionData.initialValidators[i].weight
            );
        }
        return res;
    }

    /**
     * @notice Packs a RegisterL1ValidatorMessage message into a byte array.
     * The message format specification is:
     *
     * RegisterL1ValidatorMessage:
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |               codecID :      uint16 |                                                            2 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |                typeID :      uint32 |                                                            4 bytes |
     * +-----------------------+-------------+-------------------------------------------------------------------+
     * |              subnetID :    [32]byte |                                                           32 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |                nodeID :      []byte |                                              4 + len(nodeID) bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |          blsPublicKey :    [48]byte |                                                           48 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |                expiry :      uint64 |                                                            8 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * | remainingBalanceOwner : PChainOwner |                                      8 + len(addresses) * 20 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |          disableOwner : PChainOwner |                                      8 + len(addresses) * 20 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     * |                weight :      uint64 |                                                            8 bytes |
     * +-----------------------+-------------+--------------------------------------------------------------------+
     *                                       | 122 + len(nodeID) + (len(addresses1) + len(addresses2)) * 20 bytes |
     *                                       +--------------------------------------------------------------------+
     *
     * PChainOwner:
     * +-----------+------------+-------------------------------+
     * | threshold :     uint32 |                       4 bytes |
     * +-----------+------------+-------------------------------+
     * | addresses : [][20]byte | 4 + len(addresses) * 20 bytes |
     * +-----------+------------+-------------------------------+
     *                          | 8 + len(addresses) * 20 bytes |
     *                          +-------------------------------+
     *
     * @param validationPeriod The information to pack into the message.
     * @return The validationID and the packed message.
     */
    function packRegisterL1ValidatorMessage(
        ValidationPeriod memory validationPeriod
    ) external pure returns (bytes32, bytes memory) {
        if (validationPeriod.blsPublicKey.length != 48) {
            revert InvalidBLSPublicKey();
        }

        // solhint-disable-next-line func-named-parameters
        bytes memory res = abi.encodePacked(
            CODEC_ID,
            REGISTER_L1_VALIDATOR_MESSAGE_TYPE_ID,
            validationPeriod.subnetID,
            uint32(validationPeriod.nodeID.length),
            validationPeriod.nodeID,
            validationPeriod.blsPublicKey,
            validationPeriod.registrationExpiry,
            validationPeriod.remainingBalanceOwner.threshold,
            uint32(validationPeriod.remainingBalanceOwner.addresses.length)
        );
        for (
            uint256 i;
            i < validationPeriod.remainingBalanceOwner.addresses.length;
            ++i
        ) {
            res = abi.encodePacked(
                res,
                validationPeriod.remainingBalanceOwner.addresses[i]
            );
        }
        res = abi.encodePacked(
            res,
            validationPeriod.disableOwner.threshold,
            uint32(validationPeriod.disableOwner.addresses.length)
        );
        for (
            uint256 i;
            i < validationPeriod.disableOwner.addresses.length;
            ++i
        ) {
            res = abi.encodePacked(
                res,
                validationPeriod.disableOwner.addresses[i]
            );
        }
        res = abi.encodePacked(res, validationPeriod.weight);

        return (sha256(res), res);
    }

    /**
     * @notice Unpacks a byte array as a RegisterL1ValidatorMessage message.
     * The message format specification is the same as the one used in above for packing.
     *
     * @param input The byte array to unpack.
     * @return The unpacked ValidationPeriod.
     */
    function unpackRegisterL1ValidatorMessage(
        bytes memory input
    ) external pure returns (ValidationPeriod memory) {
        uint32 index;
        ValidationPeriod memory validation;

        // Unpack the codec ID
        // Individual fields are unpacked in their own scopes to avoid stack too deep errors.
        {
            uint16 codecID;
            for (uint256 i; i < 2; ++i) {
                codecID |=
                    uint16(uint8(input[i + index])) <<
                    uint16((8 * (1 - i)));
            }
            if (codecID != CODEC_ID) {
                revert InvalidCodecID(codecID);
            }
            index += 2;
        }

        // Unpack the type ID
        {
            uint32 typeID;
            for (uint256 i; i < 4; ++i) {
                typeID |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            if (typeID != REGISTER_L1_VALIDATOR_MESSAGE_TYPE_ID) {
                revert InvalidMessageType();
            }
            index += 4;
        }

        // Unpack the subnetID
        {
            bytes32 subnetID;
            for (uint256 i; i < 32; ++i) {
                subnetID |= bytes32(
                    uint256(uint8(input[i + index])) << (8 * (31 - i))
                );
            }
            validation.subnetID = subnetID;
            index += 32;
        }

        // Unpack the nodeID length
        uint32 nodeIDLength;
        {
            for (uint256 i; i < 4; ++i) {
                nodeIDLength |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            index += 4;

            // Unpack the nodeID
            bytes memory nodeID = new bytes(nodeIDLength);
            for (uint256 i; i < nodeIDLength; ++i) {
                nodeID[i] = input[i + index];
            }
            validation.nodeID = nodeID;
            index += nodeIDLength;
        }

        // Unpack the blsPublicKey
        {
            bytes memory blsPublicKey = new bytes(48);
            for (uint256 i; i < 48; ++i) {
                blsPublicKey[i] = input[i + index];
            }
            validation.blsPublicKey = blsPublicKey;
            index += 48;
        }

        // Unpack the registration expiry
        {
            uint64 expiry;
            for (uint256 i; i < 8; ++i) {
                expiry |=
                    uint64(uint8(input[i + index])) <<
                    uint64((8 * (7 - i)));
            }
            validation.registrationExpiry = expiry;
            index += 8;
        }

        // Unpack the remainingBalanceOwner threshold
        uint32 remainingBalanceOwnerAddressesLength;
        {
            uint32 remainingBalanceOwnerThreshold;
            for (uint256 i; i < 4; ++i) {
                remainingBalanceOwnerThreshold |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            index += 4;

            // Unpack the remainingBalanceOwner addresses length
            for (uint256 i; i < 4; ++i) {
                remainingBalanceOwnerAddressesLength |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            index += 4;

            // Unpack the remainingBalanceOwner addresses
            address[] memory remainingBalanceOwnerAddresses = new address[](
                remainingBalanceOwnerAddressesLength
            );
            for (uint256 i; i < remainingBalanceOwnerAddressesLength; ++i) {
                bytes memory addrBytes = new bytes(20);
                for (uint256 j; j < 20; ++j) {
                    addrBytes[j] = input[j + index];
                }
                address addr;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    addr := mload(add(addrBytes, 20))
                }
                remainingBalanceOwnerAddresses[i] = addr;
                index += 20;
            }
            validation.remainingBalanceOwner = PChainOwner({
                threshold: remainingBalanceOwnerThreshold,
                addresses: remainingBalanceOwnerAddresses
            });
        }

        // Unpack the disableOwner threshold
        uint32 disableOwnerAddressesLength;
        {
            uint32 disableOwnerThreshold;
            for (uint256 i; i < 4; ++i) {
                disableOwnerThreshold |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            index += 4;

            // Unpack the disableOwner addresses length
            for (uint256 i; i < 4; ++i) {
                disableOwnerAddressesLength |=
                    uint32(uint8(input[i + index])) <<
                    uint32((8 * (3 - i)));
            }
            index += 4;

            // Unpack the disableOwner addresses
            address[] memory disableOwnerAddresses = new address[](
                disableOwnerAddressesLength
            );
            for (uint256 i; i < disableOwnerAddressesLength; ++i) {
                bytes memory addrBytes = new bytes(20);
                for (uint256 j; j < 20; ++j) {
                    addrBytes[j] = input[j + index];
                }
                address addr;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    addr := mload(add(addrBytes, 20))
                }
                disableOwnerAddresses[i] = addr;
                index += 20;
            }
            validation.disableOwner = PChainOwner({
                threshold: disableOwnerThreshold,
                addresses: disableOwnerAddresses
            });
        }
        // Now that we have all the variable lengths, validate the input length
        uint32 expectedLength = 122 +
            nodeIDLength +
            (remainingBalanceOwnerAddressesLength +
                disableOwnerAddressesLength) *
            20;
        if (input.length != expectedLength) {
            revert InvalidMessageLength(uint32(input.length), expectedLength);
        }
        // Unpack the weight
        {
            uint64 weight;
            for (uint256 i; i < 8; ++i) {
                weight |=
                    uint64(uint8(input[i + index])) <<
                    uint64((8 * (7 - i)));
            }
            validation.weight = weight;
        }

        return validation;
    }

    /**
     * @notice Packs a L1ValidatorRegistrationMessage into a byte array.
     * The message format specification is:
     * +--------------+----------+----------+
     * |      codecID :   uint16 |  2 bytes |
     * +--------------+----------+----------+
     * |       typeID :   uint32 |  4 bytes |
     * +--------------+----------+----------+
     * | validationID : [32]byte | 32 bytes |
     * +--------------+----------+----------+
     * |   registered :     bool |  1 byte  |
     * +--------------+----------+----------+
     *                           | 39 bytes |
     *                           +----------+
     *
     * @param validationID The ID of the validation period.
     * @param registered true if the validation period was registered, false if it was not and never will be.
     * @return The packed message.
     *
     */
    function packL1ValidatorRegistrationMessage(
        bytes32 validationID,
        bool registered
    ) external pure returns (bytes memory) {
        return
            abi.encodePacked(
                CODEC_ID,
                L1_VALIDATOR_REGISTRATION_MESSAGE_TYPE_ID,
                validationID,
                registered
            );
    }

    /**
     * @notice Unpacks a byte array as a L1ValidatorRegistrationMessage message.
     * The message format specification is the same as the one used in above for packing.
     *
     * @param input The byte array to unpack.
     * @return The validationID and whether the validation period was registered or is not a
     * validator and never will be a validator due to the expiry time passing.
     */
    function unpackL1ValidatorRegistrationMessage(
        bytes memory input
    ) external pure returns (bytes32, bool) {
        if (input.length != 39) {
            revert InvalidMessageLength(uint32(input.length), 39);
        }
        // Unpack the codec ID
        uint16 codecID;
        for (uint256 i; i < 2; ++i) {
            codecID |= uint16(uint8(input[i])) << uint16((8 * (1 - i)));
        }
        if (codecID != CODEC_ID) {
            revert InvalidCodecID(codecID);
        }

        // Unpack the type ID
        uint32 typeID;
        for (uint256 i; i < 4; ++i) {
            typeID |= uint32(uint8(input[i + 2])) << uint32((8 * (3 - i)));
        }
        if (typeID != L1_VALIDATOR_REGISTRATION_MESSAGE_TYPE_ID) {
            revert InvalidMessageType();
        }

        // Unpack the validation ID.
        bytes32 validationID;
        for (uint256 i; i < 32; ++i) {
            validationID |= bytes32(
                uint256(uint8(input[i + 6])) << (8 * (31 - i))
            );
        }

        // Unpack the validity
        bool registered = input[38] != 0;

        return (validationID, registered);
    }

    /**
     * @notice Packs a L1ValidatorWeightMessage message into a byte array.
     * The message format specification is:
     * +--------------+----------+----------+
     * |      codecID :   uint16 |  2 bytes |
     * +--------------+----------+----------+
     * |       typeID :   uint32 |  4 bytes |
     * +--------------+----------+----------+
     * | validationID : [32]byte | 32 bytes |
     * +--------------+----------+----------+
     * |        nonce :   uint64 |  8 bytes |
     * +--------------+----------+----------+
     * |       weight :   uint64 |  8 bytes |
     * +--------------+----------+----------+
     *                           | 54 bytes |
     *                           +----------+
     *
     * @param validationID The ID of the validation period.
     * @param nonce The nonce of the validation ID.
     * @param weight The new weight of the validator.
     * @return The packed message.
     */
    function packL1ValidatorWeightMessage(
        bytes32 validationID,
        uint64 nonce,
        uint64 weight
    ) external pure returns (bytes memory) {
        return
            abi.encodePacked(
                CODEC_ID,
                L1_VALIDATOR_WEIGHT_MESSAGE_TYPE_ID,
                validationID,
                nonce,
                weight
            );
    }

    /**
     * @notice Unpacks a byte array as an L1ValidatorWeightMessage.
     * The message format specification is the same as the one used in above for packing.
     *
     * @param input The byte array to unpack.
     * @return The validationID, nonce, and weight.
     */
    function unpackL1ValidatorWeightMessage(
        bytes memory input
    ) external pure returns (bytes32, uint64, uint64) {
        if (input.length != 54) {
            revert InvalidMessageLength(uint32(input.length), 54);
        }

        // Unpack the codec ID.
        uint16 codecID;
        for (uint256 i; i < 2; ++i) {
            codecID |= uint16(uint8(input[i])) << uint16((8 * (1 - i)));
        }
        if (codecID != CODEC_ID) {
            revert InvalidCodecID(codecID);
        }

        // Unpack the type ID.
        uint32 typeID;
        for (uint256 i; i < 4; ++i) {
            typeID |= uint32(uint8(input[i + 2])) << uint32((8 * (3 - i)));
        }
        if (typeID != L1_VALIDATOR_WEIGHT_MESSAGE_TYPE_ID) {
            revert InvalidMessageType();
        }

        // Unpack the validation ID.
        bytes32 validationID;
        for (uint256 i; i < 32; ++i) {
            validationID |= bytes32(
                uint256(uint8(input[i + 6])) << (8 * (31 - i))
            );
        }

        // Unpack the nonce.
        uint64 nonce;
        for (uint256 i; i < 8; ++i) {
            nonce |= uint64(uint8(input[i + 38])) << uint64((8 * (7 - i)));
        }

        // Unpack the weight.
        uint64 weight;
        for (uint256 i; i < 8; ++i) {
            weight |= uint64(uint8(input[i + 46])) << uint64((8 * (7 - i)));
        }

        return (validationID, nonce, weight);
    }

    /**
     * @notice Packs a ValidationUptimeMessage into a byte array.
     * The message format specification is:
     * +--------------+----------+----------+
     * |      codecID :   uint16 |  2 bytes |
     * +--------------+----------+----------+
     * |       typeID :   uint32 |  4 bytes |
     * +--------------+----------+----------+
     * | validationID : [32]byte | 32 bytes |
     * +--------------+----------+----------+
     * |       uptime :   uint64 |  8 bytes |
     * +--------------+----------+----------+
     *                           | 46 bytes |
     *                           +----------+
     *
     * @param validationID The ID of the validation period.
     * @param uptime The uptime of the validator.
     * @return The packed message.
     */
    function packValidationUptimeMessage(
        bytes32 validationID,
        uint64 uptime
    ) external pure returns (bytes memory) {
        return
            abi.encodePacked(
                CODEC_ID,
                VALIDATION_UPTIME_MESSAGE_TYPE_ID,
                validationID,
                uptime
            );
    }

    /**
     * @notice Unpacks a byte array as a ValidationUptimeMessage.
     * The message format specification is the same as the one used in above for packing.
     *
     * @param input The byte array to unpack.
     * @return The validationID and uptime.
     */
    function unpackValidationUptimeMessage(
        bytes memory input
    ) external pure returns (bytes32, uint64) {
        if (input.length != 46) {
            revert InvalidMessageLength(uint32(input.length), 46);
        }

        // Unpack the codec ID.
        uint16 codecID;
        for (uint256 i; i < 2; ++i) {
            codecID |= uint16(uint8(input[i])) << uint16((8 * (1 - i)));
        }
        if (codecID != CODEC_ID) {
            revert InvalidCodecID(codecID);
        }

        // Unpack the type ID.
        uint32 typeID;
        for (uint256 i; i < 4; ++i) {
            typeID |= uint32(uint8(input[i + 2])) << uint32((8 * (3 - i)));
        }
        if (typeID != VALIDATION_UPTIME_MESSAGE_TYPE_ID) {
            revert InvalidMessageType();
        }

        // Unpack the validation ID.
        bytes32 validationID;
        for (uint256 i; i < 32; ++i) {
            validationID |= bytes32(
                uint256(uint8(input[i + 6])) << (8 * (31 - i))
            );
        }

        // Unpack the uptime.
        uint64 uptime;
        for (uint256 i; i < 8; ++i) {
            uptime |= uint64(uint8(input[i + 38])) << uint64((8 * (7 - i)));
        }

        return (validationID, uptime);
    }
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

    /**
     * @notice Emitted when churn settings are updated.
     * @param churnPeriodSeconds The new churn period duration in seconds.
     * @param maximumChurnPercentage The new maximum churn percentage per period.
     */
    event ChurnSettingsUpdated(
        uint64 churnPeriodSeconds,
        uint8 maximumChurnPercentage
    );

    /**
     * @notice Updates the churn period settings.
     * @param churnPeriodSeconds The new churn period duration in seconds.
     * @param maximumChurnPercentage The new maximum churn percentage per period.
     */
    function setChurnSettings(
        uint64 churnPeriodSeconds,
        uint8 maximumChurnPercentage
    ) external;
}

