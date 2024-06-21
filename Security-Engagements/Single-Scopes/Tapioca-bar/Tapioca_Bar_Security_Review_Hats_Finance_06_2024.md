# **Tapioca (Lending Engine) Audit Competition on Hats.finance** 


## Introduction to Hats.finance


Hats.finance builds autonomous security infrastructure for integration with major DeFi protocols to secure users' assets. 
It aims to be the decentralized choice for Web3 security, offering proactive security mechanisms like decentralized audit competitions and bug bounties. 
The protocol facilitates audit competitions to quickly secure smart contracts by having auditors compete, thereby reducing auditing costs and accelerating submissions. 
This aligns with their mission of fostering a robust, secure, and scalable Web3 ecosystem through decentralized security solutions​.

## About Hats Audit Competition


Hats Audit Competitions offer a unique and decentralized approach to enhancing the security of web3 projects. Leveraging the large collective expertise of hundreds of skilled auditors, these competitions foster a proactive bug hunting environment to fortify projects before their launch. Unlike traditional security assessments, Hats Audit Competitions operate on a time-based and results-driven model, ensuring that only successful auditors are rewarded for their contributions. This pay-for-results ethos not only allocates budgets more efficiently by paying exclusively for identified vulnerabilities but also retains funds if no issues are discovered. With a streamlined evaluation process, Hats prioritizes quality over quantity by rewarding the first submitter of a vulnerability, thus eliminating duplicate efforts and attracting top talent in web3 auditing. The process embodies Hats Finance's commitment to reducing fees, maintaining project control, and promoting high-quality security assessments, setting a new standard for decentralized security in the web3 space​​.

## Tapioca (Lending Engine) Overview

The Unstoppable OmniDollar Ecosystem_ Powered by LayerZero

## Competition Details


- Type: A public audit competition hosted by Tapioca (Lending Engine)
- Duration: 10 days
- Maximum Reward: $60,000
- Submissions: 30
- Total Payout: $4,686 distributed among 6 participants.

## Scope of Audit

## Project overview


Tapioca bar, which is Tapiocas main lending engine is composed by two main markets with similar structures:



- Big Bang:

https://docs.tapioca.xyz/tapioca/core-technologies/big-bang




- Singularity:

https://docs.tapioca.xyz/tapioca/core-technologies/singularity




- The markets interact with Yieldbox;

https://docs.tapioca.xyz/tapioca/core-technologies/yieldbox




- And Big Bang is in charge on minting our CDP, USDO:

https://docs.tapioca.xyz/tapioca/token-economy/usdo







## Audit competition scope


This are the following contracts in scope from the Tapioca-bar repository:



contracts/Penrose.sol

contracts/markets/Market.sol

contracts/markets/bigBang/BBLeverage.sol

contracts/markets/bigBang/BBLiquidation.sol

contracts/markets/bigBang/BBCommon.sol

contracts/markets/bigBang/BigBang.sol

contracts/markets/bigBang/BBBorrow.sol

contracts/markets/bigBang/BBStorage.sol

contracts/markets/bigBang/BBLendingCommon.sol

contracts/markets/bigBang/BBCollateral.sol

contracts/markets/MarketStateView.sol

contracts/libraries/SafeApprove.sol

contracts/usdo/USDOFlashloanHelper.sol

contracts/usdo/Usdo.sol

contracts/markets/origins/Origins.sol

contracts/usdo/BaseUsdo.sol

contracts/usdo/BaseUsdoTokenMsgType.sol

contracts/markets/MarketERC20.sol

contracts/markets/MarketHelper.sol

contracts/markets/singularity/SGLLeverage.sol

contracts/markets/singularity/SGLBorrow.sol

contracts/markets/singularity/SGLStorage.sol

contracts/markets/singularity/SGLCommon.sol

contracts/markets/singularity/SGLLendingCommon.sol

contracts/markets/singularity/SGLCollateral.sol

contracts/markets/singularity/Singularity.sol

contracts/markets/singularity/SGLLiquidation.sol

contracts/usdo/libraries/UsdoMsgCodec.sol

contracts/usdo/libraries/RevertMsgDecoder.sol

contracts/usdo/extensions/UsdoHelper.sol

contracts/usdo/modules/UsdoOptionReceiverModule.sol

contracts/usdo/modules/ModuleManager.sol

contracts/usdo/modules/UsdoSender.sol

contracts/usdo/modules/UsdoMarketReceiverModule.sol

contracts/usdo/modules/UsdoReceiver.sol

contracts/markets/leverage/AssetTotsDaiLeverageExecutor.sol

contracts/markets/leverage/AssetToSGLPLeverageExecutor.sol

contracts/markets/leverage/BaseLeverageExecutor.sol

contracts/markets/leverage/SimpleLeverageExecutor.sol

contracts/liquidators/MarketLiquidatorReceiversol






## Medium severity issues


- **Potential for Bad-Debt Exploit in Liquidation Due to Bonus Condition Handling**

  The current algorithm for calculating the liquidation factor contains a condition to prevent liquidators from bypassing bad debt. However, the condition may not ensure the liquidator provides an adequate `maxBorrowAmount`. This can result in situations where the collateral amount is sufficient to cover the borrowed amount but not the liquidation bonus. By adjusting the `maxBorrowAmount`, a liquidator can disproportionately reduce `borrowPartWithBonus`, resulting in the borrower receiving a larger share of the liquidation bonus and exiting the protocol with uncollateralized debt. 

For example, if Alice's collateral exceeds her borrow amount but not the borrow amount plus the liquidation bonus, Bob could liquidate at an amount that leaves a portion of Alice's debt unpaid and uncollateralized. To address this, it's recommended to verify that the total debt, including the liquidation bonus, does not exceed the available collateral.


  **Link**: [Issue #14](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/14)

## Low severity issues


- **Ensuring MarketERC20 Permit Function is Invoked by Correct Spender**

  Any user can call `MarketERC20::permit` on behalf of an owner, potentially allowing front-running attacks that disrupt cross-chain actions. To mitigate this, it is recommended to check that the spender is `msg.sender` or add a field `caller` to verify the caller's identity.


  **Link**: [Issue #15](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/15)


- **Allow Collateral Repayment Without Exchange Rate Update to Prevent Debt Accumulation**

  A function used to sell collateral for debt repayment fails if the exchange rate update fails. Although crucial for market entries, this requirement should be relaxed for debt repayment to avoid excessive debt accrual. A suggestion is to modify the `solvent()` modifier to allow debt repayment even with rate update failures, preventing unnecessary debt.


  **Link**: [Issue #18](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/18)


- **Infinite Loop in Usdo.send Function Causes Gas Exhaustion**

  In the `Usdo.send` function, a recursive call causes the function to keep calling itself until gas runs out, which is incorrect. Though this flaw doesn't risk financial loss due to the `sendPacket` method usage, it still needs addressing. A reward of 150 USDC is offered for identifying this issue.


  **Link**: [Issue #22](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/22)


- **ProtocolWithdrawal Event Misconfiguration Hindering Data Emission in Penrose Contract Event**

  Using the `indexed` keyword for reference type variables like dynamic arrays or strings in events returns a hash, resulting in meaningless data for applications subscribing to these events. In the `Penrose` contract, the `ProtocolWithdrawal` event is affected, causing potential data loss on the DApp side. The solution involves modifying the event definition to emit proper parameters.


  **Link**: [Issue #27](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/27)


- **Missing updates when registering/unregistering Origins market in Penrose contract**

  The `addOriginsMarket` function in Penrose does not update the `clonesOf` and `masterContractOf` state variables as done in `addBigBang`. When attempting to unregister an `Origins` market, `unregisterContract` tries to delete `clonesOf` but doesn't update the `isOriginRegistered` flag, causing reverts.


  **Link**: [Issue #29](https://github.com/hats-finance/Tapioca--Lending-Engine--0x5bee198f5b060eecd86b299fdbea6b0c07c728dd/issues/29)



## Conclusion

The Tapioca (Lending Engine) audit competition, hosted on Hats.finance, aimed to enhance the security of the lending protocol through a decentralized, result-driven audit model. The competition, spanning 10 days, attracted 30 submissions with a total payout of $4,686 distributed among 6 participants. The audit focused on several key contracts within the Tapioca-bar repository, including those related to its core markets, Big Bang and Singularity, which are integral to its lending operations. Medium and low-severity issues were identified, such as potential bad-debt exploits in liquidations, improper invocations of the permit function in MarketERC20, and infinite loops causing gas exhaustion in the Usdo.send function. Other issues included misconfigured event protocols and missing updates when registering/unregistering markets. Overall, the audit highlighted critical areas for improvement while underscoring the efficacy of Hats.finance's decentralized approach in proactively securing Web3 projects.

## Disclaimer


This report does not assert that the audited contracts are completely secure. Continuous review and comprehensive testing are advised before deploying critical smart contracts.


The Tapioca (Lending Engine) audit competition illustrates the collaborative effort in identifying and rectifying potential vulnerabilities, enhancing the overall security and functionality of the platform.


Hats.finance does not provide any guarantee or warranty regarding the security of this project. Smart contract software should be used at the sole risk and responsibility of users.
