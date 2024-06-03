# Tapioca Dao Security Review - 2024/05/15
###### tags: `private`, `tapioca-dao`

# Introduction 
A security review of the [Tapioca Dao](https://www.tapioca.xyz/) protocol was done by Trumpero team. 

This audit report includes all the vulnerabilities, issues and code improvements found during the security review.

# Disclaimer
A smart contract security review cannot assure the absolute absence of vulnerabilities. It involves a constrained allocation of time, resources, and expertise to identify as many vulnerabilities as possible. I cannot provide a guarantee of 100% security following the review, nor can I guarantee that any issues will be discovered during the review of your smart contracts.

# About Tapioca DAO 
TapiocaDAO is a decentralized autonomous organization (DAO) which created a decentralized Omnichain stablecoin ecosystem, comprised of multiple sub-protocols, which includes; Singularity, the first-ever Omnichain isolated money market, Big Bang, an Omnichain CDP Stablecoin Creation Engine, Yieldbox, the most powerful token vault ever created, tOFT (Tapioca Omnichain Wrapper[s]) which transforms any fragmented asset into a unified Omnichain asset, twAML, an economic incentive consensus mechanism, and Pearlnet, the self-sovereign Omnichain verifier network.

# About Trumpero Team 
The Trumpero team was established by two independent smart contract researchers, Trungore and duc, who share a profound interest in Web3 security. Demonstrating their capabilities through numerous audits, contests, and bug bounties, the team is dedicated to contributing to the blockchain ecosystem and its protocols by investing significant time and effort into security research and reviews.

Twitter - [Trungore](https://twitter.com/Trungore), [duc](https://twitter.com/duc_hph) \
Sherlock - [Trumpero](https://audits.sherlock.xyz/watson/Trumpero) \
Code4rena - [KIntern_NA](https://code4rena.com/@KIntern_NA) \
Github - [Portfolio](https://github.com/Trumpero/Smart-Contract-Review-Public-Reports)

# Severity Classification
## Severity
| **Severity** | **Impact: High** | **Impact: Medium** | **Impact: Low** |
|---|---|---|---|
| **Likelihood: High** | High  | High | Medium |  
| **Likelihood: Medium** | High | Medium | Low |   
| **Likelihood: Low** | Medium | Low | Low |   
## Impact 
**High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.

**Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.

**Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

## Likelihood

**High** - attack path is possible with reasonable assumptions that mimic on-chain conditions, and the cost of the attack is relatively low compared to the amount of funds that can be stolen or lost.

**Medium** - only a conditionally incentivized attack vector, but still relatively likely.

**Low** - has too many or too unlikely assumptions or requires a significant stake by the attacker with little or no incentive.

# Audit scope
The [Tapioca-bar](https://github.com/Tapioca-DAO/Tapioca-bar) repository was audited at commit [71558e5a830a194c72ef4a9ef10a0f0997a3851e](https://github.com/Tapioca-DAO/Tapioca-bar/tree/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts)

The following contracts were in scope:
* contracts/libraries/* 
* contracts/markets/* 
* contracts/usdo/* 
* contracts/Penrose.sol 

# Findings Summary 
| ID           | Title                                                                                                                                                        | Severity | Status  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |  -------- | ------- |
| [H-01](#H01) | Incorrect Update in `_allowedBorrow()` Function Allows Attacker to Over-Spending the Allowance from user | HIGH | Fixed |
| [H-02](#H02) | Lack of verification for sellToken and buyToken within the function  | HIGH | Fixed |
| [H-03](#H03) | Risk of allowance check in the buyCollateral function: malicious spender can drain funds much more than their allowance | HIGH | Fixed |
| [H-04](#H04) | Attacker can steal user's collateral by utilizing the function `UsdoMarketreceiverModule._repay()`  | HIGH | Fixed |
| [M-01](#M01) | Unable to wrap token to `tOFT` due to lack of approval for pearlmit | MEDIUM     | Fixed |
| [M-02](#M02) | Incorrect approval amount to swapper in function `BaseLeverageExecutor._swapAndTransferToSender()` | MEDIUM     | Fixed |
| [M-03](#M03) | Unable to `_repay()` because `MagnetarAssetModule` is not implemented in the latest `tapioca-periph` repo | MEDIUM     | Fixed |
| [M-04](#M04) | Missing revert in case the allowance share is 0 in `BBLendingCommon._repay` | MEDIUM     | Fixed |
| [M-05](#M05) | The option to not accrue fees of Singularity while pausing doesn't work | MEDIUM     | Fixed |
| [M-06](#M06) | An incorrect `repayAmount` was used in the `UsdoMarketReceiverModule._repay()` function | MEDIUM     | Fixed |
| [M-07](#M07) | Missing `accrue()` for the ETH market to update the correct debt whenever accruing other BB markets | MEDIUM     | Fixed |
| [M-08](#M08) | The refund token from the swapper is not properly managed | MEDIUM     | Fixed |
| [L-01](#L01) | An incorrect number of seconds in a year was used in the `BBCommon._accrueView()` function | LOW     | Fixed |


# Detailed Findings

## <a id="High"></a>High

### <a id="H01"></a> [H-01] Incorrect Update in `_allowedBorrow()` Function Allows Attacker to Over-Spending the Allowance from user

#### Description
The function `Market._allowedBorrow()` verifies whether the caller is permitted to borrow a specified `share` from `from`.

```solidity
function _allowedBorrow(address from, uint256 share) internal virtual override {
    if (from != msg.sender) {
        if (share == 0) revert AllowanceNotValid();

        uint256 pearlmitAllowed;
        if (penrose.cluster().isWhitelisted(0, msg.sender)) {
            (pearlmitAllowed,) = penrose.pearlmit().allowance(from, msg.sender, address(yieldBox), collateralId);
        }

        require(allowanceBorrow[from][msg.sender] >= share || pearlmitAllowed >= share, "Market: not approved");
        if (pearlmitAllowed != 0) return;

        if (allowanceBorrow[from][msg.sender] != type(uint256).max) {
            allowanceBorrow[from][msg.sender] -= share;
        }
    }
}
```

According to the implementation, the caller can borrow from `from` if either:
* The built-in `allowance[from][msg.sender]` is greater than or equal to the required `share`, or
* The allowance for the `collateralId` in the YieldBox contract is greater than or equal to the required `share`.

However, there is a problem with updating `allowanceBorrow[from][msg.sender]`. This mapping won't be updated if `pearlmitAllowed` is not zero, even if this value is less than the `share`.

Consider the scenario where:
* `allowanceBorrow[from][msg.sender] = share`
* `0 < pearlmitAllowed < share`

When `allowedBorrow()` is invoked, since `pearlmitAllowed` is greater than zero, `allowanceBorrow[from][msg.sender]` remains unchanged. As a result, the caller can repeatedly invoke this function, potentially performing malicious actions (e.g., borrowing) on behalf of user `from`.

#### Impact
The attacker can borrow from the user more than the amount they have been given. 

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/Market.sol#L435-L438

#### Recommendation
Consider modifying the function `_allowedBorrow()` to: 
```solidity
function _allowedBorrow(address from, uint256 share) internal virtual override {
    if (from != msg.sender) {
        if (share == 0) revert AllowanceNotValid();

        uint256 pearlmitAllowed;
        if (penrose.cluster().isWhitelisted(0, msg.sender)) {
            (pearlmitAllowed,) = penrose.pearlmit().allowance(from, msg.sender, address(yieldBox), collateralId);
        }

        require(allowanceBorrow[from][msg.sender] >= share || pearlmitAllowed >= share, "Market: not approved");
        if (pearlmitAllowed >= share) return;

        if (allowanceBorrow[from][msg.sender] != type(uint256).max) {
            allowanceBorrow[from][msg.sender] -= share;
        }
    }
}
```
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/437

### <a id="H02"></a> [H-02] Lack of verification for sellToken and buyToken within the function 
#### Description
Within the function `BaseLeverageExecutor._swapAndTransferToSender()`, the function `swapper.swap()` is called to exchange `tokenIn` for `tokenOut`. However, there is no validation to ensure that the provided values `swapData.sellToken` and `swapData.buyToken` correspond to `tokenIn` and `tokenOut`. This lack of verification can be exploited by an attacker who uses a `swapData.buyToken` that is different from `tokenOut` to steal funds from the user.

Consider the following scenario:

0. Assume the exchange rates are:
    * 1 KNC = 1 USDO
    * 1 ETH = 50 USDO 

1. In the BigBang market where the collateral is KNC tokens, assume `allowanceBorrow[Alice][Bob] = 2`. With a `collateralizationRate` of 100%, Bob can borrow up to 2 KNC on behalf of Alice.
    * Bob transfers 2 KNC to the `leverageExecutor` contract.
    * Bob triggers the function `buyCollateral()` with:
        * `borrowAmount = 100`
        * `swapData.sellToken = USDO`
        * `swapData.buyToken = ETH` (instead of the expected collateral, KNC).
    * Since `swapData.buyToken` is ETH, Bob can swap the 100 borrowed USDO for 2 ETH. As a result, `amountOut` will be set to 2 at line [158](https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L158).
    * Since Bob has already transferred 2 KNC to the `leverageExecutor`, the transfer proceeds, and the `_allowedBorrow()` check passes because `amountOut = 2`.

    --> Thus, Bob can borrow up to 100 USDO, equivalent to 100 KNC collateral, even though Alice's allowance is only 2. This results in a loss for Alice.

2. Further investigation reveals that after step 1, 2 ETH remains in the `leverageExecutor` contract. Bob can then trigger `buyCollateral()` in the BigBang market where ETH is the collateral to redeem these ETH.
    * Bob transfers 2 KNC to the `swapper` contract to ensure the `swapper` contract has KNC to transfer to the `leverageExecutor` contract during the swap.
    * Bob triggers the `buyCollateral()` function with:
        * `borrowAmount = 2`
        * `swapData.sellToken = USDO`
        * `swapData.buyToken = KNC` (instead of the expected collateral, ETH).
    * Since `swapData.buyToken` is KNC, Bob can use 2 USDO to buy 2 KNC. After the swap, `amountOut` will be set to 2, and the `leverageExecutor` will transfer the 2 ETH to the BigBang market at lines [164 - 169](https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L164-L169).

    --> As a result, Bob can redeem 2 ETH from the `leverageExecutor`, yielding a profit of 2 ETH minus the value of 2 KNC and an additional 2 KNC.

#### Impact
An attacker can steal funds from users with a small `allowanceBorrow`.

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L140-L170

#### Recommendation
Consider ensuring that the `sellToken` and `buyToken` are the same as `tokenIn` and `tokenOut` within the function `BaseLeverageExecutor::_swapAndTransferToSender()`.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/444



### <a id="H03"></a> [H-03] Risk of allowance check in the buyCollateral function: malicious spender can drain funds much more than their allowance
#### Description
In BB and SGL markets, the flow of the `buyCollateral()` function is to supply and borrow assets first, then buy collateral with these assets. However, it checks the allowance of the sender by the final received collateral. Even when it reverts if `collateralShare` received is 0, this is still potentially vulnerable since the supply and borrow assets can be very large, but it might receive a small amount of collateral after the swap due to slippage or a malicious swap path. More details can be found in https://github.com/sherlock-audit/2024-02-tapioca-judging/issues/31.
#### Impact
Malicious users with a small allowance from others can abuse `buyCollateral` to drain or steal funds.
#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/bigBang/BBLeverage.sol#L109
#### Recommendation
`buyCollateral` function should check allowance of supply and borrow amount before swap. It is similar with allowance check while borrowing. 
```solidity=
uint256 allowanceShare = _computeAllowanceAmountInAsset(
    from, 
    exchangeRate,  
    memoryData.supplyShareToAmount + memoryData.borrowShareToAmount, 
    asset.safeDecimals());
    _allowedBorrow(from, allowanceShare
);
_allowedBorrow(from, allowanceShare);

{
    amountOut = leverageExecutor.getCollateral(
        address(asset),
        address(collateral),
        memoryData.supplyShareToAmount + memoryData.borrowShareToAmount,
        calldata_.data
    );
}
...
```
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/commit/74bc8bd503a2aeae335aa07b46a13b379d9c68c1

### <a id="H04"></a> [H-04] Attacker can steal user's collateral by utilizing the function `UsdoMarketreceiverModule._repay()` 
#### Description
The `UsdoMarketReceiverModule._repay()` function is used to forward calls from another chain to the `Magnetar` contract, specifically to the `depositRepayAndRemoveCollateralFromMarket` function of the `MagnetarCollateralModule` contract. The purpose of this function is to allow the user to perform a sequence of actions on a specific market:

1. **STEP 1**: Deposit the user's assets into YieldBox.
2. **STEP 2**: Repay debt on the market.
3. **STEP 3**: Remove collateral and withdraw the asset to a specified receiver.

To ensure that the `srcChainSender` has the necessary permissions to execute these actions, the `_repay` function includes a check `_validateAndSpendAllowance()` to verify that the `srcChainSender` has been approved to use the `depositAmount` by the `msg_.user`.

```solidity
function _repay(MarketLendOrRepayMsg memory msg_, address srcChainSender) private {
    ... 
    
    _validateAndSpendAllowance(msg_.user, srcChainSender, msg_.lendParams.depositAmount);
    
    ... 
    
    IMagnetar(payable(msg_.lendParams.magnetar)).burst{value: msg.value}(magnetarCall);
}
```

However, this check is insufficient to handle all permissions required for the actions triggered in the `MagnetarCollateralModule.depositRepayAndRemoveCollateralFromMarket()` function, especially **step 3 - collateral removal**.

Consider a scenario where an attacker who lacks approval from Alice to spend USDO uses the following parameters:
- `depositAmount = 0`
- `repayAmount = 0`
- `collateralAmount > 0`

In this case, the `_validateAndSpendAllowance()` check will succeed because the required allowance is `0`. And, the collateral removal step will be executed in the `Magnetar` contract since the provided `collateralAmount` is greater than `0`. This allows the attacker to remove the collateral on behalf of the user and send it to their own address `receiver`.

#### Impact
An attacker can steal collateral from users who have given `allowanceBorrow` to the Magnetar contract.

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/usdo/modules/UsdoMarketReceiverModule.sol#L161

#### Recommendation
Consider adding a requirement to ensure the `srcChainSender` has permission to remove collateral on behalf of the user. 
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/453/commits/534c233916498f55d92bc562524eb8985ae22452

---

## <a id="Medium"></a>Medium

### <a id="M01"></a> [M-01] Unable to wrap token to `tOFT` due to lack of approval for pearlmit
#### Description
The `TOFT.wrap()` function is designed to wrap ERC20 tokens and mint the corresponding tOFT tokens.

https://github.com/Tapioca-DAO/TapiocaZ/blob/e3c8d36fc63b64e455e0b90e270ba6f5b3d85575/contracts/tOFT/BaseTOFT.sol#L82-L94
```solidity
function _wrap(address _fromAddress, address _toAddress, uint256 _amount, uint256 _feeAmount) internal virtual {
    if (_fromAddress != msg.sender) {
        if (allowance(_fromAddress, msg.sender) < _amount) {
            revert TOFT_AllowanceNotValid();
        }
        _spendAllowance(_fromAddress, msg.sender, _amount);
    }
    if (_amount == 0) revert TOFT_NotValid();
    // IERC20(erc20).safeTransferFrom(_fromAddress, address(vault), _amount);
    bool isErr = pearlmit.transferFromERC20(_fromAddress, address(vault), erc20, _amount);
    if (isErr) revert TOFT_NotValid();
    _mint(_toAddress, _amount - _feeAmount);
}
```

As shown in the code, the `_wrap` function requires the `_fromAddress` to provide allowance for the pearlmit contract to transfer tokens from `_fromAddress` to the `TOFT` contract.

However, in the `BaseLeverageExecutor._handleToftWrapToSender()` function, instead of approving the `toftErc20` for the pearlmit contract, it is incorrectly approved for the `tOFT` contract. This misalignment causes a lack of allowance for the pearlmit contract, leading to reverted transactions.
```solidity
function _handleToftWrapToSender(bool sendBack, address tokenOut, uint256 amountOut)
    internal
    returns (uint256 _amountOut)
{
    ...
    
    } else {
        // If the tOFT is for an ERC20, wrap it.
        toftErc20.safeApprove(tokenOut, amountOut);
        _amountOut = ITOFT(tokenOut).wrap(address(this), wrapsTo, amountOut);
        toftErc20.safeApprove(tokenOut, 0);
    }
}
```

This issue also affects the `AssetToSGLPLeverageExecutor.getCollateral()` and `AssetTotsDaiLeverageExecutor.getCollateral()` functions.

#### Impact
Since the function `_handleToftWrapToSender()` is used to swap between the collateral and asset during leverage actions, this lack of allowance for pearlmit will prevent the leverage actions from being performed. 

#### Code Snippet
* https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L216-L218
* https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/AssetToSGLPLeverageExecutor.sol#L110-L112
* https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/AssetTotsDaiLeverageExecutor.sol#L62-L64

#### Recommendation
Consider giving the allowance to the `pearlmit` contract instead of the `TOFT` contract.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/commit/1723833478ca84420e21e6cd8cfb6298bae9806a

### <a id="M02"></a> [M-02] Incorrect approval amount to swapper in function `BaseLeverageExecutor._swapAndTransferToSender()`
#### Description
The `BaseLeverageExecutor._swapAndTransferToSender()` function is designed to swap `tokenIn` for `tokenOut`.

```solidity
function _swapAndTransferToSender(
    bool sendBack,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    bytes memory data
) internal returns (uint256 amountOut) {
    SLeverageSwapData memory swapData = abi.decode(data, (SLeverageSwapData));

    // If tokenIn is a tOFT, unwrap it. Handles ETH and ERC20.
    if (swapData.toftInfo.isTokenInToft) {
        (tokenIn, amountOut) = _handleToftUnwrap(tokenIn, amountIn);
    }

    // Approve the swapper to spend tokenIn and perform the swap.
    tokenIn.safeApprove(address(swapper), amountOut);
    
    ... 
}
```

Within the function, it addresses scenarios where `tokenIn` is a `tOFT` token by unwrapping it using `_handleToftUnwrap()`. This function assigns `amountOut` to the second return value of `_handleToftUnwrap()`, representing the amount of `tokenIn` to be sent to the swapper for executing the swap. Following this, the function approves `amountOut` of `tokenIn` for the swapper.

The issue arises when `tokenIn` is not a `tOFT` token. In this case, the conditional block from [line 150 to 152](https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L150-L152) is not triggered, resulting in `amountOut` being zero. Consequently, the contract approves zero `tokenIn` to the swapper, preventing the swap from being executed.


#### Impact
The `BaseLeverageExecutor._swapAndTransferToSender()` function cannot be called if `tokenIn` is not a tOFT token (e.g., DAI, USDO).

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L150-L155

#### Recommendation
Consider modifying the function to: 
```diff
function _swapAndTransferToSender(
    bool sendBack,
    address tokenIn,
    address tokenOut,
    uint256 amountIn,
    bytes memory data
) internal returns (uint256 amountOut) {
    SLeverageSwapData memory swapData = abi.decode(data, (SLeverageSwapData));


    // If the tokenIn is a tOFT, unwrap it. Handles ETH and ERC20.
    if (swapData.toftInfo.isTokenInToft) {
-        (tokenIn, amountOut) = _handleToftUnwrap(tokenIn, amountIn);
+        (tokenIn, amountIn) = _handleToftUnwrap(tokenIn, amountIn);
    }


    // Approve the swapper to spend the tokenIn, and perform the swap.
-    tokenIn.safeApprove(address(swapper), amountOut);
+    tokenIn.safeApprove(address(swapper), amountIn);
    
    ... 
}
```
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/blob/GT_zerox-swapper-refund/contracts/markets/leverage/BaseLeverageExecutor.sol#L152

### <a id="M03"></a> [M-03] Unable to `_repay()` because `MagnetarAssetModule` is not implemented in the latest `tapioca-periph` repo
#### Description
In the latest [update](https://github.com/Tapioca-DAO/tapioca-periph/tree/dev) for the `tapioca-periph` repository, the `MagnetarAssetModule` contract has been merged into the `MagnetarCollateralModule` contract, so it is no longer implemented separately. However, a necessary fix has not been applied to the `UsdoMarketReceiverModule` contract.

```solidity=
function _repay(MarketLendOrRepayMsg memory msg_, address srcChainSender) private {
    ...    

    bytes memory call = abi.encodeWithSelector(
        MagnetarAssetModule.depositRepayAndRemoveCollateralFromMarket.selector,
        ... 
    );

    MagnetarCall[] memory magnetarCall = new MagnetarCall[](1);
    magnetarCall[0] = MagnetarCall({
        id: uint8(MagnetarAction.AssetModule),
        ...
    });
    
    ...
}
```

In the `UsdoMarketReceiverModule._repay()` function, the `call` variable is encoded using the selector of the `MagnetarAssetModule.depositRepayAndRemoveCollateralFromMarket` function, which is now part of the `MagnetarCollateralModule` contract. Additionally, `magnetarCall[0].id` is assigned the value `uint8(MagnetarAction.AssetModule)`, which no longer exists.

#### Impact
The `UsdoMarketReceiverModule._repay()` function cannot be triggered.

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L140-L170

#### Recommendation
Consider changing 
* `MagnetarAssetModule` to `MagnetarCollateralModule` 
* `MagnetarAction.AssetModule` to `MagnetarAction.CollateralModule`
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/429/files

### <a id="M04"></a> [M-04] Missing revert in case the allowance share is 0 in `BBLendingCommon._repay`
#### Description
```solidity=
In `BBLendingCommon._repay`, it checks the allowance of the sender when the `checkAllowance` flag is on.
function _repay(address from, address to, uint256 part, bool checkAllowance) internal returns (uint256 amount) {
        if (part > userBorrowPart[to]) {
            part = userBorrowPart[to];
        }
        if (part == 0) revert NothingToRepay();

        // @dev check allowance
        if (checkAllowance && msg.sender != from) {
            uint256 partInAmount;
            Rebase memory _totalBorrow = totalBorrow;
            (_totalBorrow, partInAmount) = _totalBorrow.sub(part, true);
            uint256 allowanceShare =
                _computeAllowanceAmountInAsset(to, exchangeRate, partInAmount, _safeDecimals(asset));
            _allowedLend(from, allowanceShare);
        }
```
`allowanceShare` used to check the allowance is calculated by the `_computeAllowanceAmountInAsset` function with `partInAmount` and will be rounded down. Therefore, `allowanceShare` can be 0 when `partInAmount` is too small. Hence, the sender doesn't need any allowance to call repay on behalf of the user, and it will repay and burn the user's asset unexpectedly.
```solidity=
function _computeAllowanceAmountInAsset(
        address user,
        uint256 _exchangeRate,
        uint256 borrowAmount,
        uint256 assetDecimals
    ) internal view returns (uint256) {
        uint256 maxBorrowable = _computeMaxBorrowableAmount(user, _exchangeRate);

        uint256 shareRatio = _getRatio(borrowAmount, maxBorrowable, assetDecimals);
        return (shareRatio * userCollateralShare[user]) / (10 ** assetDecimals);
    }
```
#### Impact
An attacker can repay on behalf of a user maliciously without any allowance.

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/bigBang/BBLendingCommon.sol#L119-L121
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/singularity/SGLLendingCommon.sol#L106-L108

#### Recommendation
Add a check to validate that `allowanceShare` is greater than 0 in case the `checkAllowance` flag is on.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/449

### <a id="M05"></a> [M-05] The option to not accrue fees of Singularity while pausing doesn't work
#### Description 
In the Singularity contract, there is an option to not accrue fees during the paused period if `resetAccrueTimestamp` is set to true when unpausing the market. In that case, it won't accrue fees and will update `accrueInfo.lastAccrued` to block.timestamp to skip the fee for the paused period.
```solidity=
function updatePause(PauseType _type, bool val, bool resetAccrueTimestmap) external {
      if (msg.sender != conservator) revert NotAuthorized();
      if (val == pauseOptions[_type]) revert SameState();
      emit PausedUpdated(_type, pauseOptions[_type], val);
      pauseOptions[_type] = val;

      if (val) {
          _accrue();
      }

      // In case of 'unpause', `lastAccrued` is set to block.timestamp
      // Valid for all action types that has an impact on debt or supply
      if (!val && (_type != PauseType.AddCollateral && _type != PauseType.RemoveCollateral)) {
          accrueInfo.lastAccrued = resetAccrueTimestmap ? block.timestamp.toUint64() : accrueInfo.lastAccrued;
      }
  }
```
However, the fee for SGL can be accrued by anyone using the accrue() function in the SGLCommon contract. Therefore, when the admin attempts to pause SGL without accruing the fee, it doesn't work if anyone calls accrue() during the paused period.

#### Impact
The fee for SGL may be forced to accrue during the paused period.
#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/singularity/Singularity.sol#L273-L288
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/singularity/SGLCommon.sol#L40-L42
#### Recommendation
Only allow `accrue()` when SGL is not paused for PauseType.AddCollateral and PauseType.RemoveCollateral.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/451

### <a id="M06"></a> [M-06] An incorrect `repayAmount` was used in the `UsdoMarketReceiverModule._repay()` function
#### Description
In the `UsdoMarketReceiverModule._repay()` function, if the `repayAmount` parameter is set to `0`, it will be recalculated as the borrow part corresponding to the provided `depositAmount`. This implies that the entire deposit amount will be used to repay the user's debt.

```solidity
function _repay(MarketLendOrRepayMsg memory msg_, address srcChainSender) private {
    if (msg_.lendParams.repayAmount == 0) {
        msg_.lendParams.repayAmount = IMagnetarHelper(IMagnetar(payable(msg_.lendParams.magnetar)).helper())
            .getBorrowPartForAmount(msg_.lendParams.market, msg_.lendParams.depositAmount);
    }
    ...
}
```

This recalculated amount is then passed as `data.repayAmount` to the `depositRepayAndRemoveCollateralFromMarket()` function of the `MagnetarCollateralModule`, which subsequently calls `_marketRepay()`.

```solidity=
function depositRepayAndRemoveCollateralFromMarket(DepositRepayAndRemoveCollateralFromMarketData memory data)
    public
    payable
{
    ... 

    if (data.repayAmount > 0) {
        _market.accrue();
        _marketRepay(_market, data.marketHelper, data.repayAmount, data.user, data.user);
    }
    
    ... 
}
```

However, an issue arises in the `MagnetarBaseModule._marketRepay()` function, where the input `data.repayAmount` is converted to the borrow part again, even though this conversion was already performed in the `UsdoMarketReceiverModule._repay()` function.

```solidity= 
/// link: https://github.com/Tapioca-DAO/tapioca-periph/blob/c8938a1d48bbc78923ad00837c544b54b05e6be1/contracts/Magnetar/modules/MagnetarCollateralModule.sol#L167-L170
function _marketRepay(IMarket _market, address _marketHelper, uint256 _amount, address _from, address _to)
    internal
    returns (uint256 repayed)
{
    uint256 repayPart = helper.getBorrowPartForAmount(address(_market), _amount);
    
    ...
}
```

#### Impact
The user will repay an incorrect amount of debt. 

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/usdo/modules/UsdoMarketReceiverModule.sol#L156-L159

#### Recommendation
If `repayAmount == 0`, consider setting it to `depositAmount` to use the entire deposit amount for repayment.

```diff
function _repay(MarketLendOrRepayMsg memory msg_, address srcChainSender) private {
    if (msg_.lendParams.repayAmount == 0) {
-        msg_.lendParams.repayAmount = IMagnetarHelper(IMagnetar(payable(msg_.lendParams.magnetar)).helper()).getBorrowPartForAmount(msg_.lendParams.market, msg_.lendParams.depositAmount);
+        msg_.lendParams.repayAmount = msg_.lendParams.depositAmount;
    }
    
    ...
}
```
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/452

### <a id="M07"></a> [M-07] Missing `accrue()` for the ETH market to update the correct debt whenever accruing other BB markets
#### Description
Whenever the debt of the ETH Bigbang market is updated, it calls `penrose.reAccrueBigBangMarkets()` to accrue all other BB markets right after accruing the ETH market in `solvent()`.
```solidity=
function borrow(address from, address to, uint256 amount)
        external
        optionNotPaused(PauseType.Borrow)
        notSelf(to)
        solvent(from)
        returns (uint256 part, uint256 share)
    {
        if (amount == 0) return (0, 0);
        penrose.reAccrueBigBangMarkets();
```
```solidity=
function reAccrueBigBangMarkets() external notPaused {
        if (msg.sender == bigBangEthMarket) {
            _reAccrueMarkets(false);
        }
    }

    function _reAccrueMarkets(bool includeMainMarket) private {
        uint256 len = allBigBangMarkets.length;
        address[] memory markets = allBigBangMarkets;
        for (uint256 i; i < len; i++) {
            address market = markets[i];
            if (isMarketRegistered[market]) {
                if (includeMainMarket || market != bigBangEthMarket) {
                    IBigBang(market).accrue();
                }
            }
        }

        emit ReaccruedMarkets(includeMainMarket);
    }
```
This is because the `getDebtRate()` function of other BB markets uses the total debt of the ETH market for its calculations, the markets will accrue debt by this debt rate.

However, when accruing other markets, it doesn't accrue the ETH market to update the correct total debt of the ETH market. This leads to an inconsistency in the debt rate of these markets when accruing. Therefore, the accrued debt will be different than expected.
#### Impact
Due to the inconsistency in debt accruing in BB markets, the accrued debt will be different than expected
#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/bigBang/BBCommon.sol#L88-L119
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/bigBang/BBCommon.sol#L49
#### Recommendation
Before accruing in any operation, BB markets that are not the ETH market should call `accrue()` for the ETH market to update the correct debt.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/454

### <a id="M08"></a> [M-08] The refund token from the swapper is not properly managed
#### Description
Within the `ZeroXSwapper.swap()` function, any unused input tokens are returned to the sender after a successful swap to the `swapTarget`.

https://github.com/Tapioca-DAO/tapioca-periph/blob/c8938a1d48bbc78923ad00837c544b54b05e6be1/contracts/Swapper/ZeroXSwapper.sol#L82-L87
```solidity
function swap(SZeroXSwapData calldata swapData, uint256 amountIn, uint256 minAmountOut)
    public
    payable
    returns (uint256 amountOut)
{
    ...
    
    if (amountInBefore > amountInAfter) {
        uint256 transferred = amountInBefore - amountInAfter;
        if (transferred < amountIn) {
            swapData.sellToken.safeTransfer(msg.sender, amountIn - transferred);
        }
    }
    
    ... 
}
```

However, the `BaseLeverageExecutor._swapAndTransferToSender()` function, which interacts with the swapper during the swap to the collateral or asset token, does not account for these returned tokens. This omission can result in a loss for the user if the entire input amount is not fully utilized. 

#### Impact
loss of token in when input amount is not fully utilized 

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/leverage/BaseLeverageExecutor.sol#L158

#### Recommendation
Consider modifying the `BaseLeverageExecutor._swapAndTransferToSender()` function to return any remaining input tokens to the `msg.sender`. Additionally, this returned amount should be managed within the `BBLeverage` and `SGLLeverage` contracts after invoking `leverageExecutor.getCollateral()` or `leverageExecutor.getAsset()`.
#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/421

---

## <a id="Low"></a>Low 

### <a id="L01"></a> [L-01] An incorrect number of seconds in a year was used in the `BBCommon._accrueView()` function
#### Description
In the `BBCommon._accrueView()` function, the value `31536000` is used to represent the number of seconds in a year. However, this value does not account for leap years. The correct value, `31557600`, representing the number of seconds per year, should be used instead. This correct value is already utilized in the `_accrue()` function, whereas `31536000` is mistakenly used in `_accrueView()`.

#### Impact
The function `BBCommon._accrueView()` computes an incorrect return value for elastic, which impacts the calculations in the `Market.computeTVLInfo()` function.

#### Code Snippet
https://github.com/Tapioca-DAO/Tapioca-bar/blob/71558e5a830a194c72ef4a9ef10a0f0997a3851e/contracts/markets/bigBang/BBCommon.sol#L79

#### Recommendation
Consider using `31557600` as the number of seconds in a year.

#### Discussion
Protocol team: fixed - https://github.com/Tapioca-DAO/Tapioca-bar/pull/455