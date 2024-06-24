/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type {
  IReferralFeePool,
  IReferralFeePoolInterface,
} from "../IReferralFeePool";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "_recipient",
        type: "address",
      },
    ],
    name: "addReward",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

export class IReferralFeePool__factory {
  static readonly abi = _abi;
  static createInterface(): IReferralFeePoolInterface {
    return new utils.Interface(_abi) as IReferralFeePoolInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): IReferralFeePool {
    return new Contract(address, _abi, signerOrProvider) as IReferralFeePool;
  }
}
