// (c) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: LicenseRef-Ecosystem

pragma solidity 0.8.25;

import {IRewardCalculator} from "./interfaces/IRewardCalculator.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts@5.0.2/access/Ownable2Step.sol";

/**
 * @title FixedAPRRewardCalculator
 * @notice A reward calculator that provides a fixed APR (Annual Percentage Rate)
 * based on actual uptime. Uses simple interest (no compounding).
 *
 * ## Linear Reward Model
 *
 * Rewards are calculated proportionally to actual uptime:
 * - reward = stakeAmount * APR * periodUptimeSeconds / SECONDS_IN_YEAR
 * - No minimum uptime threshold - validators earn rewards for any uptime
 * - This ensures fair compensation: more uptime = more rewards
 */
contract FixedAPRRewardCalculator is IRewardCalculator, Ownable2Step {
    uint256 public constant SECONDS_IN_YEAR = 31536000;

    uint16 public constant BIPS_CONVERSION_FACTOR = 10000;

    /// @notice Maximum allowed reward basis points (100% APR = 10000 basis points)
    uint64 public constant MAX_REWARD_BASIS_POINTS = 10000;

    /// @notice The reward rate in basis points (e.g., 500 = 5% APR)
    uint64 public rewardBasisPoints;

    /// @notice Emitted when the reward basis points is updated
    event RewardBasisPointsUpdated(uint64 oldBasisPoints, uint64 newBasisPoints);

    /// @notice Error thrown when reward basis points is zero
    error ZeroRewardBasisPoints();

    /// @notice Error thrown when reward basis points exceeds maximum
    error RewardBasisPointsExceedsMax(uint64 provided, uint64 maximum);

    constructor(uint64 rewardBasisPoints_, address initialOwner) Ownable(initialOwner) {
        if (rewardBasisPoints_ == 0) {
            revert ZeroRewardBasisPoints();
        }
        if (rewardBasisPoints_ > MAX_REWARD_BASIS_POINTS) {
            revert RewardBasisPointsExceedsMax(rewardBasisPoints_, MAX_REWARD_BASIS_POINTS);
        }
        rewardBasisPoints = rewardBasisPoints_;
    }

    /**
     * @notice Updates the reward basis points
     * @param newRewardBasisPoints The new reward rate in basis points
     */
    function setRewardBasisPoints(uint64 newRewardBasisPoints) external onlyOwner {
        if (newRewardBasisPoints == 0) {
            revert ZeroRewardBasisPoints();
        }
        if (newRewardBasisPoints > MAX_REWARD_BASIS_POINTS) {
            revert RewardBasisPointsExceedsMax(newRewardBasisPoints, MAX_REWARD_BASIS_POINTS);
        }
        uint64 oldBasisPoints = rewardBasisPoints;
        rewardBasisPoints = newRewardBasisPoints;
        emit RewardBasisPointsUpdated(oldBasisPoints, newRewardBasisPoints);
    }

    /**
     * @notice Calculate incremental reward for claiming during active staking.
     * @dev This allows validators and delegators to claim rewards without ending their stake.
     *
     * Linear reward model - rewards are proportional to actual uptime:
     * - reward = stakeAmount * APR * periodUptimeSeconds / SECONDS_IN_YEAR
     * - No minimum uptime threshold required
     *
     * See {IRewardCalculator-calculateIncrementalReward}
     *
     * @param stakeAmount The amount of tokens staked
     * @param lastClaimTime The timestamp of the last reward claim (or staking start if first claim)
     * @param currentTime The current timestamp
     * @param lastClaimUptimeSeconds The uptime seconds at the last claim
     * @param currentUptimeSeconds The current uptime seconds
     * @param validatorStartTime The timestamp when the validator started (unused but kept for interface compatibility)
     * @return reward The calculated reward amount
     */
    function calculateIncrementalReward(
        uint256 stakeAmount,
        uint64 lastClaimTime,
        uint64 currentTime,
        uint64 lastClaimUptimeSeconds,
        uint64 currentUptimeSeconds,
        uint64 validatorStartTime
    ) external view returns (uint256 reward) {
        // Silence unused variable warning
        validatorStartTime;

        // Calculate the time period for this claim
        uint64 periodDuration = currentTime - lastClaimTime;
        if (periodDuration == 0) {
            return 0;
        }

        // Calculate uptime for this period
        uint64 periodUptimeSeconds = currentUptimeSeconds -
            lastClaimUptimeSeconds;

        // Linear reward: proportional to actual uptime
        // reward = stakeAmount * rewardBasisPoints * periodUptimeSeconds / (SECONDS_IN_YEAR * BIPS_CONVERSION_FACTOR)
        return
            (stakeAmount * rewardBasisPoints * periodUptimeSeconds) /
            (SECONDS_IN_YEAR * BIPS_CONVERSION_FACTOR);
    }
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

