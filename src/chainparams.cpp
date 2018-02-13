// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ZCC";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        //TODO - change this
        consensus.fPowAllowMinDifficultyBlocks = true;
        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 8037;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         * >>> from pyblake2 import blake2s
         * >>> 'Zclassic' + blake2s(b'No taxation without representation. BTC #437541 - 00000000000000000397f175a94dd3f530b957182eb2a9f7b79a44a94a5e0450').hexdigest()
         */
        /*
        *from pyblake2 import blake2s
        *pz = 'ZcashGold' + blake2s(b'2018-Jan-31: SP500 close at 2,823.81. BTC Block 507015 Hash 0000000000000000005ff5fcb4f0a053cc27405015741075ea75acb5c74c75d9.')    .hexdigest()
        *print(pz) 
        *ZcashGold33ca611910719839fabdf5dc41c9ade4ddd21f34edaaf721adbf2757de587a7c
         */
        const char* pszTimestamp = "ZcashGold33ca611910719839fabdf5dc41c9ade4ddd21f34edaaf721adbf2757de587a7c";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1517494329;
        genesis.nBits    = 0x1f07ffff;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000602");
        genesis.nSolution = ParseHex("0040757950ce3aca72e1a3428b313c11048feff24020a386eeec2ea4add73db3b3872e3409d93ab6d52c0a6721daea1df1a9e462241f8ed60c82537dfa396e2740c53d0850a5fd4d2327c5dd4b7d7eced91753f304fda24ecd53230aa29010b7cb76ecdd1a431a894a225473711d51be3101bf4505854e6a59843879ca040722a1fa08a83eb78c4b79940c4dc39b47773caec109aa7a9c3a84252c9f2f519bddda9628881c64f5dd01e1f135ca07dc8d88de516183a30e54b23e75a4060a3dfa387e32d5f1984ac4601c407481fd8b14269305ecdcf565060db7d09bc63a93622d21f7b75f61f50bbf47e0b44e73e5888b2827d273ac5694795d04d803f937ff700c42679894b2357d2dff191b5cdb7b09251729b63e147cbae07c841a234ce4c570ce8f7837117f90c7b9b23f93edc5c369c6f9ddacf8acd720752a832bed8dd4c416f810b35a0ac7b419008869635a026c01199a2d3057e4e2d212f7328a225e1eb8b02307398a02ae85d147784c143e1ea658a1366c3f5cbf094cf0dc280c33bd30881727724d3f222085f1aa501baf622b0c5eb23786fdd4d1dbb5f2568f87be58d40c18aad9b5586c53e27c4216a37b46e8c442735a3d185c39e7b2944e5d8854144b99ec578aec2d9e768a0c44807fd74891fbc5e2a4de2267376df883356a2c2c729fcaa2263a0ba07b7471a4fbac2143083838d008114d13c582b34fdee5e3d0e748e5f545f456a1cd41676ce9451e4177b011e6ad8f76d6ee2538de95140db7d239c36076931c26418a4177d45d8cf0f07571133cfffb034752b3dccd252133af9685cca8d48b8e0d63c4ec929edef357fd21a99ae308e604ac9e0bbb1e2317d2628f879da78cd66297cbb769a2aa95247212d729d1ac491ef5478a01cf0a8f69c875fde5188b2ea374d6fe91f1f7c6054772306317cddf6491efad02fa34a5e7c5bb0bf2c574fadc2f4dde51d21cda852fbf253242572e87fc8944b9885afee2ed9dddcf7411049bdb9c071c7ebc6e4125a9786f94e19854c47427a71a291912afd1b147733c729d89e136eecbd9fc0f2492af06e25d21b1902184afec3e777a671d5d0d8349c4de67fddc1df06539271a68700b19c579c9e819690dfd424e337d9986a6697ae95de230cd5cb66d1c63cf3b499e037df803e276f9f6ec173915de9eba0726fdfc8e2155d7e6a5d3d729df4cb9bfb0bf7139309d1f48f8652b592fe106e130f6a0b9dd4d5a56db0b52060e1bcebf16843993b685d54505c88110947b455dbf0c846dfd8d7938e751a55ceee708f798d34b0a9a8f179155a3ecede8e317eca2934167e4b10e6014d3dbe66f94adedb95e64d455cf7f9e27ecb2aadf0e34d19727d4a3fd6bbcd62a27739dfb0e401e4d4f124cc269665e190ef92017ac3859748f7bbd9c13fd040276991181b5f375dd92179a222983a1859e32b2160ae21181b15751cbf83253bbcbf3b558865e0e150b839ef4a28f0a5909cd41e2939a087e33aff9d73c31ec8418fa5d45bba0b334c61cddfbce2cef3cde74091aea7f3156248953d7f3b0e7bb06e92cdeda991034c61e70ea928247b260643a8eb3dd5e4105f4dc7d1710b7f1ac0fc11293e7c3a414d948b5c79c529abf3a273ad87029c57fd4e6b4f116ebe9de887bb7ef6d0b0f079289e2dfab8092131579d00dd93502cbb7ec16184994c70d84cf4e91749deb553dc1e290af90480ff333ec75f4dfc7ed3d0231c8684410d6fbf6459019440addf2d5e8b2d23783faee60626ba9e8be190511c45358e3739583a13796ee9ffca28e5367d4dda92282c46c491b1a5d0453284d2f721916d5ec99721219ce3364bb4a3785e70ba2ae9cb838460f6d16f42e2293d748c2a04773800312bb6e51ed66863fb7dd25");

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x00048d7568583533f57b02d184ea376a306b0a75a0ed20ad4570c472f84a79b0"));
        assert(genesis.hashMerkleRoot == uint256S("0xdf50526e37eaa4e54f1f09e3f15794fd30430e076368446039e934f002fd525c"));

        vFixedSeeds.clear();
        vSeeds.clear();

        //vSeeds.push_back(CDNSSeedData("zclassic.org", "dnsseed.zclassic.org")); // zclassic
        //vSeeds.push_back(CDNSSeedData("indieonion.org", "dnsseed.indieonion.org")); // @IndieOnion
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "dnsseed.rotorproject.org")); // @IndieOnion

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,  // * UNIX timestamp of last checkpoint block
            0,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            0               // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };
        /*
        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
            ( 30000, uint256S("0x000000005c2ad200c3c7c8e627f67b306659efca1268c9bb014335fdadc0c392"))
            ( 160000, uint256S("0x000000065093005a1a46ee95d6d66c2b07008220ca64dd3b3a93bbd1945480c0")),
            1502742046,     // * UNIX timestamp of last checkpoint block
            392489,          // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1413            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };
        */

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//          "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd", /* main-index: 0*/
//            "t3cL9AucCajm3HXDhb5jBnJK2vapVoXsop3", /* main-index: 1*/
//            "t3fqvkzrrNaMcamkQMwAyHRjfDdM2xQvDTR", /* main-index: 2*/
//            "t3TgZ9ZT2CTSK44AnUPi6qeNaHa2eC7pUyF", /* main-index: 3*/
//            "t3SpkcPQPfuRYHsP5vz3Pv86PgKo5m9KVmx", /* main-index: 4*/
//            "t3Xt4oQMRPagwbpQqkgAViQgtST4VoSWR6S", /* main-index: 5*/
//            "t3ayBkZ4w6kKXynwoHZFUSSgXRKtogTXNgb", /* main-index: 6*/
//            "t3adJBQuaa21u7NxbR8YMzp3km3TbSZ4MGB", /* main-index: 7*/
//            "t3K4aLYagSSBySdrfAGGeUd5H9z5Qvz88t2", /* main-index: 8*/
//            "t3RYnsc5nhEvKiva3ZPhfRSk7eyh1CrA6Rk", /* main-index: 9*/
//            "t3Ut4KUq2ZSMTPNE67pBU5LqYCi2q36KpXQ", /* main-index: 10*/
//            "t3ZnCNAvgu6CSyHm1vWtrx3aiN98dSAGpnD", /* main-index: 11*/
//            "t3fB9cB3eSYim64BS9xfwAHQUKLgQQroBDG", /* main-index: 12*/
//            "t3cwZfKNNj2vXMAHBQeewm6pXhKFdhk18kD", /* main-index: 13*/
//            "t3YcoujXfspWy7rbNUsGKxFEWZqNstGpeG4", /* main-index: 14*/
//            "t3bLvCLigc6rbNrUTS5NwkgyVrZcZumTRa4", /* main-index: 15*/
//            "t3VvHWa7r3oy67YtU4LZKGCWa2J6eGHvShi", /* main-index: 16*/
//            "t3eF9X6X2dSo7MCvTjfZEzwWrVzquxRLNeY", /* main-index: 17*/
//            "t3esCNwwmcyc8i9qQfyTbYhTqmYXZ9AwK3X", /* main-index: 18*/
//            "t3M4jN7hYE2e27yLsuQPPjuVek81WV3VbBj", /* main-index: 19*/
//            "t3gGWxdC67CYNoBbPjNvrrWLAWxPqZLxrVY", /* main-index: 20*/
//            "t3LTWeoxeWPbmdkUD3NWBquk4WkazhFBmvU", /* main-index: 21*/
//            "t3P5KKX97gXYFSaSjJPiruQEX84yF5z3Tjq", /* main-index: 22*/
//            "t3f3T3nCWsEpzmD35VK62JgQfFig74dV8C9", /* main-index: 23*/
//            "t3Rqonuzz7afkF7156ZA4vi4iimRSEn41hj", /* main-index: 24*/
//            "t3fJZ5jYsyxDtvNrWBeoMbvJaQCj4JJgbgX", /* main-index: 25*/
//            "t3Pnbg7XjP7FGPBUuz75H65aczphHgkpoJW", /* main-index: 26*/
//            "t3WeKQDxCijL5X7rwFem1MTL9ZwVJkUFhpF", /* main-index: 27*/
//            "t3Y9FNi26J7UtAUC4moaETLbMo8KS1Be6ME", /* main-index: 28*/
//            "t3aNRLLsL2y8xcjPheZZwFy3Pcv7CsTwBec", /* main-index: 29*/
//            "t3gQDEavk5VzAAHK8TrQu2BWDLxEiF1unBm", /* main-index: 30*/
//            "t3Rbykhx1TUFrgXrmBYrAJe2STxRKFL7G9r", /* main-index: 31*/
//            "t3aaW4aTdP7a8d1VTE1Bod2yhbeggHgMajR", /* main-index: 32*/
//            "t3YEiAa6uEjXwFL2v5ztU1fn3yKgzMQqNyo", /* main-index: 33*/
//            "t3g1yUUwt2PbmDvMDevTCPWUcbDatL2iQGP", /* main-index: 34*/
//            "t3dPWnep6YqGPuY1CecgbeZrY9iUwH8Yd4z", /* main-index: 35*/
//            "t3QRZXHDPh2hwU46iQs2776kRuuWfwFp4dV", /* main-index: 36*/
//            "t3enhACRxi1ZD7e8ePomVGKn7wp7N9fFJ3r", /* main-index: 37*/
//            "t3PkLgT71TnF112nSwBToXsD77yNbx2gJJY", /* main-index: 38*/
//            "t3LQtHUDoe7ZhhvddRv4vnaoNAhCr2f4oFN", /* main-index: 39*/
//            "t3fNcdBUbycvbCtsD2n9q3LuxG7jVPvFB8L", /* main-index: 40*/
//            "t3dKojUU2EMjs28nHV84TvkVEUDu1M1FaEx", /* main-index: 41*/
//            "t3aKH6NiWN1ofGd8c19rZiqgYpkJ3n679ME", /* main-index: 42*/
//            "t3MEXDF9Wsi63KwpPuQdD6by32Mw2bNTbEa", /* main-index: 43*/
//            "t3WDhPfik343yNmPTqtkZAoQZeqA83K7Y3f", /* main-index: 44*/
//            "t3PSn5TbMMAEw7Eu36DYctFezRzpX1hzf3M", /* main-index: 45*/
//            "t3R3Y5vnBLrEn8L6wFjPjBLnxSUQsKnmFpv", /* main-index: 46*/
//            "t3Pcm737EsVkGTbhsu2NekKtJeG92mvYyoN", /* main-index: 47*/
////            "t3PZ9PPcLzgL57XRSG5ND4WNBC9UTFb8DXv", /* main-index: 48*/
////            "t3L1WgcyQ95vtpSgjHfgANHyVYvffJZ9iGb", /* main-index: 49*/
////            "t3JtoXqsv3FuS7SznYCd5pZJGU9di15mdd7", /* main-index: 50*/
////            "t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
////            "t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN", /* main-index: 52*/
////            "t3T4WmAp6nrLkJ24iPpGeCe1fSWTPv47ASG", /* main-index: 53*/
////            "t3fP6GrDM4QVwdjFhmCxGNbe7jXXXSDQ5dv", /* main-index: 54*/
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "ZCT";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 18037;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1517494329;
        genesis.nBits = 0x1f07ffff;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000602");
        genesis.nSolution = ParseHex("0040757950ce3aca72e1a3428b313c11048feff24020a386eeec2ea4add73db3b3872e3409d93ab6d52c0a6721daea1df1a9e462241f8ed60c82537dfa396e2740c53d0850a5fd4d2327c5dd4b7d7eced91753f304fda24ecd53230aa29010b7cb76ecdd1a431a894a225473711d51be3101bf4505854e6a59843879ca040722a1fa08a83eb78c4b79940c4dc39b47773caec109aa7a9c3a84252c9f2f519bddda9628881c64f5dd01e1f135ca07dc8d88de516183a30e54b23e75a4060a3dfa387e32d5f1984ac4601c407481fd8b14269305ecdcf565060db7d09bc63a93622d21f7b75f61f50bbf47e0b44e73e5888b2827d273ac5694795d04d803f937ff700c42679894b2357d2dff191b5cdb7b09251729b63e147cbae07c841a234ce4c570ce8f7837117f90c7b9b23f93edc5c369c6f9ddacf8acd720752a832bed8dd4c416f810b35a0ac7b419008869635a026c01199a2d3057e4e2d212f7328a225e1eb8b02307398a02ae85d147784c143e1ea658a1366c3f5cbf094cf0dc280c33bd30881727724d3f222085f1aa501baf622b0c5eb23786fdd4d1dbb5f2568f87be58d40c18aad9b5586c53e27c4216a37b46e8c442735a3d185c39e7b2944e5d8854144b99ec578aec2d9e768a0c44807fd74891fbc5e2a4de2267376df883356a2c2c729fcaa2263a0ba07b7471a4fbac2143083838d008114d13c582b34fdee5e3d0e748e5f545f456a1cd41676ce9451e4177b011e6ad8f76d6ee2538de95140db7d239c36076931c26418a4177d45d8cf0f07571133cfffb034752b3dccd252133af9685cca8d48b8e0d63c4ec929edef357fd21a99ae308e604ac9e0bbb1e2317d2628f879da78cd66297cbb769a2aa95247212d729d1ac491ef5478a01cf0a8f69c875fde5188b2ea374d6fe91f1f7c6054772306317cddf6491efad02fa34a5e7c5bb0bf2c574fadc2f4dde51d21cda852fbf253242572e87fc8944b9885afee2ed9dddcf7411049bdb9c071c7ebc6e4125a9786f94e19854c47427a71a291912afd1b147733c729d89e136eecbd9fc0f2492af06e25d21b1902184afec3e777a671d5d0d8349c4de67fddc1df06539271a68700b19c579c9e819690dfd424e337d9986a6697ae95de230cd5cb66d1c63cf3b499e037df803e276f9f6ec173915de9eba0726fdfc8e2155d7e6a5d3d729df4cb9bfb0bf7139309d1f48f8652b592fe106e130f6a0b9dd4d5a56db0b52060e1bcebf16843993b685d54505c88110947b455dbf0c846dfd8d7938e751a55ceee708f798d34b0a9a8f179155a3ecede8e317eca2934167e4b10e6014d3dbe66f94adedb95e64d455cf7f9e27ecb2aadf0e34d19727d4a3fd6bbcd62a27739dfb0e401e4d4f124cc269665e190ef92017ac3859748f7bbd9c13fd040276991181b5f375dd92179a222983a1859e32b2160ae21181b15751cbf83253bbcbf3b558865e0e150b839ef4a28f0a5909cd41e2939a087e33aff9d73c31ec8418fa5d45bba0b334c61cddfbce2cef3cde74091aea7f3156248953d7f3b0e7bb06e92cdeda991034c61e70ea928247b260643a8eb3dd5e4105f4dc7d1710b7f1ac0fc11293e7c3a414d948b5c79c529abf3a273ad87029c57fd4e6b4f116ebe9de887bb7ef6d0b0f079289e2dfab8092131579d00dd93502cbb7ec16184994c70d84cf4e91749deb553dc1e290af90480ff333ec75f4dfc7ed3d0231c8684410d6fbf6459019440addf2d5e8b2d23783faee60626ba9e8be190511c45358e3739583a13796ee9ffca28e5367d4dda92282c46c491b1a5d0453284d2f721916d5ec99721219ce3364bb4a3785e70ba2ae9cb838460f6d16f42e2293d748c2a04773800312bb6e51ed66863fb7dd25");
        consensus.hashGenesisBlock = genesis.GetHash();
        printf("testnet. genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("testnet. genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x00048d7568583533f57b02d184ea376a306b0a75a0ed20ad4570c472f84a79b0"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("zclassic.org", "dnsseed.testnet.zclassic.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
        /*
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t27ktmq1kbeCWiQ5TZ7w5npSzcdbBmTB7v6",
            "t2GcBttAKD2WTHka8HyGc2dfvVTKYZUfHmJ", "t2Q3vxWaD9LrdqUE8Xd9Ddjpr9pUQ2aGotK", "t2TTfWDsYu998fHWzVP9Gns4fgxXXRi1Wzu", "t2KS6R4MMWdSBMjLCiw2iMyhWGRQPmyRqDn",
            "t2Q2ELrgotWv3Eec6LEtMMiiQ8dtW38u8Tj", "t2AEgJA88vTWAKqxJDFUEJWyHUtQAZi5G1D", "t2HCSdmpq1TQKksuwPQevwAzPTgfJ2rkMbG", "t2HQCPFAUQaUdJWHPhg5pPBxit7inaJzubE",
            "t2Fzqvq8Y9e6Mn3JNPb982aYsLmq4b5HmhH", "t2HEz7YZQqDUgC5h4y2WSD3mWneqJNVRjjJ", "t2GCR1SCk687Eeo5NEZ23MLsms7JjVWBgfG", "t2KyiPR9Lztq2w1w747X6W4nkUMAGL8M9KN",
            "t2UxymadyxSyVihmbq7S1yxw5dCBqJ1S4jT", "t2AVeMy7fdmTcJhckqiKRG8B7F1vccEhSqU", "t26m7LwihQzD2sH7ZVhYpPJM5j7kzwbfKW9", "t2DgwUNTe7NxuyPU6fxsB5xJXap3E4yWXrN",
            "t2U6funcXA11fC9SZehyvUL3rk3Vhuh7fzS", "t284JhyS8LGM72Tx1porSqwrcq3CejthP1p", "t29egu8QcpzKeLoPLqWS6QVMnUUPQdF6eNm", "t29LqD9p9D3B26euBwFi6mfcWu8HPA38VNs",
            "t28GsAMCxAyLy85XaasddDzaYFTtfewr86y", "t2GV44QyaikQPLUfm6oTfZnw71LLjnR7gDG", "t2U2QzNLQ1jtAu4L6xxVnRXLBsQpQvGRR2g", "t2QKGr5PNan7nrwDgseyHMN9NFeeuUjCh8b",
            "t2AfS8u6HwBeJpKpbuxztvRjupKQDXqnrwa", "t2CTRQUViQd3CWMhnKhFnUHqDLUyTxmWhJs", "t2CbM9EqszNURqh1UXZBXYhwp1R4GwEhWRE", "t2LM7uYiAsKDU42GNSnMwDxbZ8s1DowQzYH",
            "t2AgvT35LHR378AE3ouz6xKMhkTLHLJC6nD", "t285EAQXUVyi4NMddJv2QqTrnv45GRMbP8e", "t2EpMRCD5b8f2DCQ37npNULcpZhkjC8muqA", "t2BCmWXrRPiCeQTpizSWKKRPM5X6PS7umDY",
            "t2DN7X6wDFn5hYKBiBmn3Z98st419yaTVTH", "t2QJj8HeCwQ6mHwqekxxDLZntYpZTHNU62t", "t2QdHBR1Yciqn4j8gpS8DcQZZtYetKvfNj3", "t2E5cpLA1ey5VNxFNcuopeQMq2rH2NHiPdu",
            "t2EVRGtzjFAyz8CF8ndvLuiJu7qZUfDa93H", "t2KoQDk3BSFadBkuaWdLwchFuQamzw9RE4L", "t2FnR3yhTmuiejEJeu6qpidWTghRd1HpjLt", "t2BAuBAAospDc9d1u5nNGEi6x4NRJBD2PQ2",
            "t2RtKrLCGcyPkm4a4APg1YY9Wu2m4R2PgrB", "t28aUbSteZzBq2pFgj1K1XNZRZP5mMMyakV", "t2Urdy1ERfkvsFuy6Z4BkhvYGzWdmivfAFR", "t2ADinR4JrvCMd4Q1XGALPajzFrirqvhED6",
        */
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        genesis.nTime = 1296688602;
        genesis.nBits = 0x200f0f0f;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        genesis.nSolution = ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3");
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18033;
        printf("regnet. genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
        printf("regnet. genesis.hashMerkleRoot = %s\n", genesis.hashMerkleRoot.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0xa0690c45a9e1985b0fcf4b22c8d7e7330e1a33057c126757e92cfcd826a49edb"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        //vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
    vFoundersRewardAddress = { };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
