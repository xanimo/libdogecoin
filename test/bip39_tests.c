/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Copyright (c) 2022 edtubbs                                         *
 * Copyright (c) 2022 bluezr                                          *
 * Copyright (c) 2022 The Dogecoin Foundation                         *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "utest.h"
#include <assert.h>

#include <dogecoin/bip39.h>
#include <dogecoin/utils.h>

void test_mnemonic()
{
	static const char *vectors[] = {
		"00000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		"80808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
		"ffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
		"000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
		"808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
		"ffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
		"8080808080808080808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
		"77c2b00716cec7213839159e404db50d",
		"jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",
		"b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
		"renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",
		"3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
		"dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",
		"0460ef47585604c5660618db2e6a7e7f",
		"afford alter spike radar gate glance object seek swamp infant panel yellow",
		"65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",
		"72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
		"indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",
		"2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
		"clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",
		"eaebabb2383351fd31d703840b32e9e2",
		"turtle front uncle idea crush write shrug there lottery flower risk shell",
		"bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",
		"7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
		"kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",
		"4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
		"exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",
		"18ab19a9f54a9274f03e5209a2ac8a91",
		"board flee heavy tunnel powder denial science ski answer betray cargo cat",
		"6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",
		"18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
		"board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",
		"15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
		"beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		"b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd",
		0,
		0,
		0,
	};

	get_words("eng");
	const char **a, **b, **c, *m;
	uint8_t seed[64];

	a = vectors;
	b = vectors + 1;
	c = vectors + 2;
	while (*a && *b && *c) {
		m = mnemonic_from_data(utils_hex_to_uint8(*a), strlen(*a) / 2);
		assert(strcmp(m, *b) == 0);
		mnemonic_to_seed(m, "TREZOR", seed, 0);
		assert(memcmp(seed, utils_hex_to_uint8(*c), strlen(*c) / 2) == 0);
#if USE_BIP39_CACHE
		// try second time to check whether caching results work
		mnemonic_to_seed(m, "TREZOR", seed, 0);
		assert(memcmp(seed, utils_hex_to_uint8(*c), strlen(*c) / 2) == 0);
#endif
		a += 3; b += 3; c += 3;
	}
}

void test_mnemonic_check()
{
	static const char *vectors_ok[] = {
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"afford alter spike radar gate glance object seek swamp infant panel yellow",
		"indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"turtle front uncle idea crush write shrug there lottery flower risk shell",
		"kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"board flee heavy tunnel powder denial science ski answer betray cargo cat",
		"board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		0,
	};
	static const char *vectors_fail[] = {
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"above winner thank year wave sausage worth useful legal winner thank yellow",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"above alter spike radar gate glance object seek swamp infant panel yellow",
		"above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"above front uncle idea crush write shrug there lottery flower risk shell",
		"above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"above flee heavy tunnel powder denial science ski answer betray cargo cat",
		"above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"winner thank year wave sausage worth useful legal winner thank yellow",
		"advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"alter spike radar gate glance object seek swamp infant panel yellow",
		"race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"front uncle idea crush write shrug there lottery flower risk shell",
		"carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"flee heavy tunnel powder denial science ski answer betray cargo cat",
		"blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		0,
	};

	get_words("eng");
	const char **m;
	int r;
	m = vectors_ok;
	while (*m) {
		r = mnemonic_check(*m);
		u_assert_int_eq(r, 1);
		m++;
	}
	m = vectors_fail;
	while (*m) {
		r = mnemonic_check(*m);
		u_assert_int_eq(r, 0);
		m++;
	}
}

void test_bip39()
{
    const char* test_mnemonic_12 = "chief prevent advice search broccoli dish pride grow evidence bicycle cushion lady";
    const char* test_mnemonic_15 = "engine link summer museum gift sphere half void where long copper mandate push valve enhance";
    const char* test_mnemonic_18 = "outside clarify pizza swim section menu current kite step nothing actor smoke swarm chronic ritual vanish cinnamon cotton";
    const char* test_mnemonic_21 = "turtle shock bar amount damp ostrich door quick smart woman tell hobby mansion duty common calm curious audit exist napkin verb";
    const char* test_mnemonic_24 = "depth artist same second negative vehicle van owner strong catch wreck salute fall lady nest sense champion foil switch become mule notable fame aerobic";

    const char* test_mnemonic_12_jpn = "ねんいり　でんち　くうぼ　そよかぜ　ななおし　さかな　るいせき　なのか　こえる　たいら　ねんまつ　くのう";
    const char* test_seed_12_jpn = "5b503adf88021a6438989c35647458d531cac635f0b5783990db2934bf5216ab6df09ec0cf81221c3bbecfebdf1bb7ea45c20cf68a4536cfbd745fe1e0bcd10a";

    const char* test_mnemonic_15_jpn = "りかい　めんどう　はそん　せつび　はにかむ　あんぜん　こちょう　けんない　つたえる　しゃれい　せんか　えいぶん　ゆたか　そらまめ　たまる";
    const char* test_seed_15_jpn = "be5a9e28d6963f510b25e68e080bc937c0a006dc3e703b324d6296f519ed9dc6efb92958690ea03b2e10a22946abdf9285cb824bcfb737cf08e99d031e414816";

    const char* test_mnemonic_18_jpn = "なふだ　のみもの　えんちょう　にんそう　ふっかつ　はろうぃん　つわもの　てんかい　さんみ　うったえる　ともる　ばかり　しひょう　すうせん　せこう　さつまいも　たぼう　すろっと";
    const char* test_seed_18_jpn = "e7dde84dad6e16e4d7dbd89d8f428e97d8501fa4e8ca8debbfdc5790134d405688e750847e883c2b9eceaab532029e78125c184e2158e640e313966154b89863";

    const char* test_mnemonic_21_jpn = "ぐんたい　てぬき　ひさしぶり　ていさつ　しまう　ひりつ　ひやす　ゆちゃく　りれき　きのう　たおす　ぬぐいとる　しむける　ねんりょう　むりょう　とつにゅう　おもたい　せまい　がっこう　ぜんぶ　おもたい";
    const char* test_seed_21_jpn = "ffbf25e2b5cee4838ae30694a86f2bc8e867641adececdde182e164908632a9966e3733f5e28849434ff9a898fe3a2ed6d05c25cd7654edd9d625a7a231b211f";

    const char* test_mnemonic_24_jpn = "ぜっく　へらす　くのう　けんちく　えんげき　でっぱ　しあわせ　せっかく　いれい　こんかい　ていおん　ぞんび　せんえい　おうたい　りせい　たんにん　こうすい　ゆれる　てんさい　いりょう　すはだ　ばんぐみ　うつる　ほいく";
    const char* test_seed_24_jpn = "b68f2864826537e17f61bc5fe6d142d711b853f4aedf033b5d6e38d2a554fdbac1143287cfb2bfd650b89472692c5c1fc0b25d491846004fd01be8f4ab5c7439";

    const char* test_mnemonic_12_spa = "suelo tribu filtro probar mortal limón risa pueblo plaza oreja tutor mambo";
    const char* test_seed_12_spa = "356b6fc9e52ac2b872d9f56048f58346ff1526c014dd5019e64f45f4fee43873f570a1c181ddd81bfa91dd442da13282eb031833efb50554f387446e3c10c455";

    const char* test_mnemonic_15_spa = "tono cordón llave cetro negar fachada impar mar jabón azufre sacar aumento tropa lazo sartén";
    const char* test_seed_15_spa = "87587a1d17cb36470b6d372d8cf32c1897639b8884ab5ef3fc5b05eb35f7cccdc463836bd8b6112f36020330df9c4e517cedbfdb282782a1323ffbd0517e360d";

    const char* test_mnemonic_18_spa = "ecuador sello justo peine aporte mando estar tabla viral traer vacuna pitón código ebrio camello adoptar farmacia niño";
    const char* test_seed_18_spa = "666268e83f039eff8ce27a215dfd9debcd3c3fe15347c130f36d87ec7bb99a26422617e1157c08c2a2bd4c0dfcddeaf497482095dd1f09870462971bddf2490f";

    const char* test_mnemonic_21_spa = "límite fábrica juntar lástima loción poeta botín cuerda rechazo niñez ser asesor salón bonsái folleto capucha mercado barco ébano reacción agregar";
    const char* test_seed_21_spa = "1be238fda08ecc34e14e71066c4e6bcb49db52191663e114d64a2c1eaa1a89aaeb4cd6789800ff29d71a1ced979dfaa21daedcf5818bb3afc0ad4255153e554a";

    const char* test_mnemonic_24_spa = "bocina gajo pausa empeño evadir rotar sala tórax latir inmenso riqueza brazo empate aval urna astuto agregar masivo divino justo vajilla ligero ocre filete";
    const char* test_seed_24_spa = "9b5a8911d37bb23f72a17af0fe8e98fe97132e81b239478ee1ae0543dfe9852fe1db5bc9f172a421c3656093a6c07b5db0a72d55daefc3d979f8f27d5008f592";


    const char* test_mnemonic_12_sc = "船 弓 十 凡 抽 渠 隆 项 牵 追 跟 非";
    const char* test_seed_12_sc = "03eb61243f0459ffe45c435b04adb5f0b681b08326c61560899c4b1b13c3cbb8aee8f66909d175fd4fe0b59b5f0d42a2efb4a48de1515adbfc5be1e35bc11b7a";

    const char* test_mnemonic_15_sc = "湾 砖 摆 续 粮 破 塑 精 值 藏 食 飞 换 摊 缺";
    const char* test_seed_15_sc = "7b4580f94058c8edee646bbc42f85b5e43f0ec7c70747443601bdc03d1a7fcbb47701cd8f277f1b75868b5fe01d8ba8c8bfa6da46e2f9feea27ebb8b42087f0c";

    const char* test_mnemonic_18_sc = "林 情 钉 纳 置 渡 沿 浅 算 开 或 睛 钻 斤 武 迁 独 物";
    const char* test_seed_18_sc = "8bfd7485d9e1d26f2a8a500dd93a13e720f00f499621c2d7300dc846ea972366e9649505b7ec6f2e81eb282582e4ff9c3ce462a776397fd3d0b6ef2bb38ea394";

    const char* test_mnemonic_21_sc = "致 纤 家 言 乎 又 饿 残 辛 经 在 同 刘 寻 版 莫 胎 月 孩 抽 本";
    const char* test_seed_21_sc = "58abf72e35b6b8fd27f45295c08d419545b7bae6cee4c4896a9469dfb7c2e85801e7acdaf053f545c3cc9783245d6b3fb08028e8ba50fe3c3ec74217b20fcd44";

    const char* test_mnemonic_24_sc = "团 样 洛 此 相 乌 郑 效 成 饱 浇 持 贡 齿 村 弯 低 欧 暗 锦 泥 异 野 仪";
    const char* test_seed_24_sc = "17af4b558add20c219d9aeef74d8dfef2c2884d2e9ccb4f7e3b0c229414447fcea9695b8488c82800eb81072e868cca37a95ca2ef8783e4a1eda757e6d64e9ff";


    const char* test_mnemonic_12_tc = "船 弓 十 凡 抽 渠 隆 項 牽 追 跟 非";
    const char* test_seed_12_tc = "339754cbf29d76b22974d574846ab5673364d55392e40135dbecd0604b2dcb9c495ec8428f94be2c30ed5a7d503de8410b700d73121c13126f0ad79b3e80a184";

    const char* test_mnemonic_15_tc = "萊 搭 準 幸 邁 線 密 羽 搜 淨 鬼 蔥 端 獄 義";
    const char* test_seed_15_tc = "481f18790dc36d00cc44cbf2b78b134304c14d02a9978ca6ed46d4480050f6a3f734402acfc60f43e42acb5809ad5a72c84b773c7ea826dc847e28bbd2d74ebb";

    const char* test_mnemonic_18_tc = "東 惡 伸 原 呆 落 喝 滲 貯 裁 久 抹 提 或 雅 為 傾 摩";
    const char* test_seed_18_tc = "8dc2b209ced582b1521d0ebca87feeecba7ed8dad3ba926887045c8e82861daf2e4985ecbcd35df01e7d1ecf8d3e61695543738fb2a9324551375c689db37c9c";

    const char* test_mnemonic_21_tc = "育 富 熟 疊 值 籍 直 牲 躺 權 凡 彈 承 涼 期 盡 欲 社 華 禁 疆";
    const char* test_seed_21_tc = "06dfb8571fc57cee1cc2d2e411a0f07b5952860aa92b38e46c9305a3044d2647482d87d4b5aafc587863fa5569a303bb2839e13b8e3401b1ff3c0d6645918169";

    const char* test_mnemonic_24_tc = "請 煩 岸 孟 徹 食 歪 塘 租 產 青 賽 任 態 呼 驗 對 格 又 某 迎 郎 陰 堡";
    const char* test_seed_24_tc = "a6c984b2df85b28737961644725d88cf829fb109cf658fcb5b487ccc46c634f4b10cff1808c21b9707078ec0936da799660fb5e93ded92aa8425b36994288914";


    const char* test_mnemonic_12_fra = "bureau créature clairon cravate duperie wagon chance naufrage soucieux xénon spécial social";
    const char* test_seed_12_fra = "559c4edd65377217a6763fcd94da5a84f258d8d59c04d083d08072ada86cf8050bfadbab2ac67519f7b971ac7fdc3b34844195e4910b5c6df0747516e5642461";

    const char* test_mnemonic_15_fra = "niche refrain balcon élégant tangible bassin incolore pluie meilleur visqueux luxueux adverbe hélium problème jeunesse";
    const char* test_seed_15_fra = "5e349ef532853110ea73006f536216da753028fffa07909e83fa9715f8c4c14cb89e14e22b958659da673003a572bf2ffc6305ef9cb17e99adfba830111aec65";

    const char* test_mnemonic_18_fra = "pleurer seigneur sérum daigner opter filière proverbe arbitre crémeux météore cendrier prison jupon dialogue brousse acteur larme suspect";
    const char* test_seed_18_fra = "98dcf7d46ca99ad70f079a96e4a0143b51f13c7231d2699a4bd334e1cbb3361c4e30dade67be7b3f9c01b817205200cfc6b76f71dfb6c7874889a782c776702d";

    const char* test_mnemonic_21_fra = "négliger boussole olivier jongler boussole saboter quiétude blinder inventer éléphant douter titane surprise domicile éblouir capuche amusant hésiter exceller obstacle hommage";
    const char* test_seed_21_fra = "c76e657e9d486afaca17ec1b6d1613da99625bfffb8674786d43bb9cd0f9097497b8e3bcde02fe65c80a6c12ea7eeb805ad19753a04235da8076acca39aea603";

    const char* test_mnemonic_24_fra = "mélange borne fictif minorer éclipse roseau caféine sirop précieux haricot durcir congeler relief serrure tarder redouter effrayer isoler électron lithium vipère salive employer associer";
    const char* test_seed_24_fra = "12f59f6d1a88248e53799c99c3b1d79e53c517d2fdd0ce678053c8756e049bd7fa7e33235cdd3f2ee5828ff97cf4842bc7b313db19e80305515f7c44aa127883";


    const char* test_mnemonic_12_ita = "recluta rinomato insano pomodoro recinto mini sorpasso zotico parola sisma oliato radicale";
    const char* test_seed_12_ita = "934f7e1f5ef8a213d3114b0d472d90db2553b54244b9a12b7be08b22ab3523199d2a1b45366ea3715336d4bc04db78b5edb080ca76bc43236ecc143bc1d80dae";

    const char* test_mnemonic_15_ita = "sinusoide eroe gemello gasdotto avvolgere etnico energia miele convegno proteso infilare gastrico etilico acqua baldo";
    const char* test_seed_15_ita = "3819320a5253380f6218d084c565aef4d41990a0250cdba1da4694301cd2c1f363a6cdb735be63c70debada8c0621396a1d36045a7aa510c4a64d42881326c9e";

    const char* test_mnemonic_18_ita = "peloso attrito elfico sociale druido insetto amanita figurato inondato pinna aria pagina raddoppio savana valanga grande labbro scrutinio";
    const char* test_seed_18_ita = "23daa08ff94cbc8a3e7025a926785c0a2fd68d95f2c770ed218897d52f2bf9d9fb20e2337c6c79b0f68ff07b99cde348198519cb6e2e7c53c617a81bcb99e993";

    const char* test_mnemonic_21_ita = "balcone barocco rinascita limpido scoprire pallido malgrado guadagno gruppo seccatura svuotare cratere fascia forbito alcolico gittata baraonda equatore giusto risvolto maiolica";
    const char* test_seed_21_ita = "4f068bbb923656eb7d4e6f51afae5c4c5a8e5651f2be1799b34feb5cfd045f220b6cf1dfbfa774e38961551d2fda8622921a33d760b56ef63a58080fd5b0ffba";

    const char* test_mnemonic_24_ita = "abbinato prudente pesista zelante occasione malsano dubitare autunno ricco pallido perbene brevetto pretesto mucca roco roccia svizzera mughetto cometa impacco accadere ridicolo cavillo esteso";
    const char* test_seed_24_ita = "7ae437607fb83f2edf24b8458f2580828558aeb696ef8d5b09c82106f047bc81ab325cdcd1b3d612be89fc9ae5ca4d2044f96b5234c63bffdda09eb12365d34a";


    const char* test_mnemonic_12_kor = "운반 입학 정문 장미 철도 인근 반죽 큰아들 복숭아 발달 저곳 첫째";
    const char* test_seed_12_kor = "2d94c81f2a3806404ef54c07b3d028bd2930480d2dcb305ff0e9f0a45328787ac6b2b4e447bb0e085dfc416c7950889151a8a842fa27a1fccef72d17fb42102b";

    const char* test_mnemonic_15_kor = "기간 수시로 야간 포스터 야단 월드컵 메일 비닐 비둘기 방향 제대로 무조건 증거 합격 방해";
    const char* test_seed_15_kor = "6920b40e52d0007f3e41d218fb814af3be1fafb76da33512c9b60fd4e7fce549173232fd406a797aea721660b56140c8d06df1def66621f62beb6ad58ae74395";

    const char* test_mnemonic_18_kor = "백두산 컬러 채널 인천 부친 검토 토요일 빛깔 기술 사나이 이렇게 구입 정부 광주 부담 평균 예약 페인트";
    const char* test_seed_18_kor = "46089b89d2af2b61ec96330bae5bc5058482957f69b2c73594f111dfd77c9d890b5b2d601a5b103c81c553abed890e1dec409f164ceb3b7fec30664d644e44b5";

    const char* test_mnemonic_21_kor = "튼튼히 재생 성질 녹음 유럽 일곱 침대 농촌 수입 시각 설악산 여섯 성질 안경 하필 외국 하느님 조정 처음 사건 퇴근";
    const char* test_seed_21_kor = "4cf73edeb76c7febc972e135321841b6a7e455e55f785fcc40f5559dadcadc065c477fef15a65080b7d18edf99da6e59a817255fa11537fff6ed0e98a8f69acb";

    const char* test_mnemonic_24_kor = "피망 검사 한꺼번에 객관적 계단 발달 경고 우승 제안 직장 골짜기 일회용 절약 유치원 감소 인형 그제서야 찬물 방법 몸속 여학생 잠깐 현지 큰아들";
    const char* test_seed_24_kor = "642855a8f4c22bf922896fcc7279123fb0d3bd919f365a4dac0bf481314179d25bf052f09681cfbab956b7ab7844a8e98f665056ad646ad4dde0ad47d68a0b60";


    const char* test_mnemonic_12_cze = "pazneht minulost pointa stavba situace farmacie obilnice makovice koleda expedice tvrdost imunita";
    const char* test_seed_12_cze = "fed95cb2957ff74b6669d6311e115eb559779c71e113206993cb6bc45494f5ad20efbf96681180a2764090ac47db72a896e20d181e3fae113943583f8466a70f";

    const char* test_mnemonic_15_cze = "svorka rasovna vyklopit pomsta vrstva mudrc konkurs spis kamkoliv studna krach pedagog kokos rukavice koalice";
    const char* test_seed_15_cze = "5361394d4a10e0839e404f73c364fa742dca4aeee26f91be8777dfb154a12e83501a46b4d8aaaa9497efd415d675d7f8b5680f534c0e2d91aa421b8370fe2ec4";

    const char* test_mnemonic_18_cze = "mnohem genetika celkem podcenit glazura chirurg kostka bobr smetana srdce evoluce hejno klasika doklad mutace lentilka leckdy zarazit";
    const char* test_seed_18_cze = "3b199ca5b5979ef18f70538a89229976aac3cabeb24b85d8c90a913e853e3be07d2e45864c284a10440d65ff8384ccb6637f67f498ba4a390be6c5831f7c669c";

    const char* test_mnemonic_21_cze = "osnova andulka petice vzdychat odsoudit zlost hravost obal rekrut sypat kupodivu bezmoc hotovost pohovor monstrum kotel rychlost rydlo nadobro bageta tuzemsko";
    const char* test_seed_21_cze = "f8eb833e09e88cd51c7a9f7e15d06b6e143d2fb83a21610bc9cfb63cac4edcb4048f70861fe03e3fe474cf2deb2cb23b7372e03decc313bc8e4a91dcc959367f";

    const char* test_mnemonic_24_cze = "svorka aktovka penze chrup ustlat cinkot omeleta naslepo pracovat chrup volno najisto budka dosyta internet malina mikrofon disk vlevo diktovat vymezit linoleum dolar snaha";
    const char* test_seed_24_cze = "45ebe3babee8dd301edce6e0208b3383ce88420aa2ee420ba0e3bdef734e1d624ad262a664caaa444d4fcc6d5ffd3c0a16ab610a32043334dd4b67e5107d679a";


    const char* test_mnemonic_12_por = "recente beldade beleza lacre molinete roleta gazela comover caju trindade dedicado greve";
    const char* test_seed_12_por = "05fd0c3a7ad7abdc37cd87b67ba14c4234d9c5fe565a53b65a274a6ed93e6b3dccb19ba741e919caff04abbea8fea1ee067774228122019cf1b301a644f688ba";

    const char* test_mnemonic_15_por = "simular nordeste recente gordura rabanada limoeiro predador informal esponja soja ateu fraterno bendito rabisco faixa";
    const char* test_seed_15_por = "a48adaa52c74c25cb2208e7f85fc9aea499876510ba9e11f95bae70335e1c7442bba8611bd00b1a29b48642b994c17d58568305f592b1bb0f9d47ac6ff721bfd";

    const char* test_mnemonic_18_por = "canivete agora samurai perceber sinopse atalho erguido dosagem beldade jorrar drogaria abater linda enlatar cobaia uniforme desenho saliva";
    const char* test_seed_18_por = "fc0771a4daee0a05da18b8bc21f359366f671fb572db8b2c991526c296a1d03c53c0c2a6a7fc4c9c7717c1ad9e71afab425ee44a36388a138572d993e6db9d7e";

    const char* test_mnemonic_21_por = "genro piscar coquetel voar ringue retalho biosfera rouco gaiola palito fera damasco insulto cerrado glicose patrono rosto tanto fungo quente disquete";
    const char* test_seed_21_por = "f3d4a0be131851a0a6d9f77356d1edfc81e19baf799460fd4ee3d976423bd7b9ec0513e437bb49fd7e65d92b991c686c3ee07dfa0f3469bd15795b1a6d068e76";

    const char* test_mnemonic_24_por = "caule rotina vertente prece lousa genro focinho grampo embutido locador chumbo espumar melhor abranger cortejo sugador povoar alocar chave bolha tarraxa apesar isolado quina";
    const char* test_seed_24_por = "a1996cc0f01b82b8af10af4563bbb907a9bd82c6e16e8632fe617a5d63f2eed6f33181c8358f77ddd8f461476ac6faee548523c6512400e55341d8b0215e0351";


    uint8_t seed [64] = "";
    uint8_t seed_test [512 / 8];

    /* generate mnemonic(s) */
    /* todo: stub entropy and generate test mnemonics */
    dogecoin_generate_mnemonic ("128", "eng");
    dogecoin_generate_mnemonic ("160", "eng");
    dogecoin_generate_mnemonic ("192", "eng");
    dogecoin_generate_mnemonic ("224", "eng");
    dogecoin_generate_mnemonic ("256", "eng");

    dogecoin_generate_mnemonic ("128", "jpn");
    dogecoin_generate_mnemonic ("160", "jpn");
    dogecoin_generate_mnemonic ("192", "jpn");
    dogecoin_generate_mnemonic ("224", "jpn");
    dogecoin_generate_mnemonic ("256", "jpn");

    dogecoin_generate_mnemonic ("128", "spa");
    dogecoin_generate_mnemonic ("160", "spa");
    dogecoin_generate_mnemonic ("192", "spa");
    dogecoin_generate_mnemonic ("224", "spa");
    dogecoin_generate_mnemonic ("256", "spa");

    dogecoin_generate_mnemonic ("128", "sc");
    dogecoin_generate_mnemonic ("160", "sc");
    dogecoin_generate_mnemonic ("192", "sc");
    dogecoin_generate_mnemonic ("224", "sc");
    dogecoin_generate_mnemonic ("256", "sc");

    dogecoin_generate_mnemonic ("128", "tc");
    dogecoin_generate_mnemonic ("160", "tc");
    dogecoin_generate_mnemonic ("192", "tc");
    dogecoin_generate_mnemonic ("224", "tc");
    dogecoin_generate_mnemonic ("256", "tc");

    dogecoin_generate_mnemonic ("128", "fra");
    dogecoin_generate_mnemonic ("160", "fra");
    dogecoin_generate_mnemonic ("192", "fra");
    dogecoin_generate_mnemonic ("224", "fra");
    dogecoin_generate_mnemonic ("256", "fra");

    dogecoin_generate_mnemonic ("128", "ita");
    dogecoin_generate_mnemonic ("160", "ita");
    dogecoin_generate_mnemonic ("192", "ita");
    dogecoin_generate_mnemonic ("224", "ita");
    dogecoin_generate_mnemonic ("256", "ita");

    dogecoin_generate_mnemonic ("128", "kor");
    dogecoin_generate_mnemonic ("160", "kor");
    dogecoin_generate_mnemonic ("192", "kor");
    dogecoin_generate_mnemonic ("224", "kor");
    dogecoin_generate_mnemonic ("256", "kor");

    dogecoin_generate_mnemonic ("128", "cze");
    dogecoin_generate_mnemonic ("160", "cze");
    dogecoin_generate_mnemonic ("192", "cze");
    dogecoin_generate_mnemonic ("224", "cze");
    dogecoin_generate_mnemonic ("256", "cze");

    dogecoin_generate_mnemonic ("128", "por");
    dogecoin_generate_mnemonic ("160", "por");
    dogecoin_generate_mnemonic ("192", "por");
    dogecoin_generate_mnemonic ("224", "por");
    dogecoin_generate_mnemonic ("256", "por");

    /* generate seed */
    /* mnemonic vectors */
    /* iancoleman.io/bip39 */

    /* English with passphrase */
    mnemonic_to_seed(test_mnemonic_12, "TREZOR", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8("31113f96716b7d5b8d58a49c5e1f6d6300ff307b35eef3cecfdb97869e514ad330f0a7dcec4ed2feeebf8d2267ebfefeb149df84642ca091befd25ea15d36076"),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15, "TREZOR", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8("7de0820caafcfc0695724ed19c3f35531c1f290650a0b39c053e67175979ed05dfedc824dcf9ac38cbc014fa86a2836c5b5e3b9ab1b9f0f84a76c492a04665b0"),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18, "TREZOR", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8("fffa2ea3c80653436c24f629581a4b3daf9843fab6f524f642aa71ffbeab7b6ce7aaa1ea03fb3686eb3b661bd2ee80bc5c42b3e94d91d40bd89a3bf9319428a2"),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21, "TREZOR", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8("706f79690efe53f124b30caf062603229735dbee0431aa7832a047ef6456a045c33d7274ef8ed97fc23bd1aaf0b02a3d50d91196ae9a9a005fbf90e76ddbce08"),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24, "TREZOR", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8("65b6c6b1e71980836b3c98ca9fd879d32e1d225c7095e3c17e68ea6daf2ea856b6e04f05e0d4a627b8d82975319b83e0dff0ab817d8e25646287f51b06b44af4"),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    /* Japanese */
    mnemonic_to_seed(test_mnemonic_12_jpn, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_jpn),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);


    mnemonic_to_seed(test_mnemonic_15_jpn, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_jpn),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);


    mnemonic_to_seed(test_mnemonic_18_jpn, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_jpn),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_jpn, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_jpn),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_jpn, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_jpn),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

   /* Spanish */
    mnemonic_to_seed(test_mnemonic_12_spa, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_spa),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_spa, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_spa),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_spa, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_spa),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_spa, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_spa),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_spa, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_spa),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

   /* Chinese (Simplified) */
    mnemonic_to_seed(test_mnemonic_12_sc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_sc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_sc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_sc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_sc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_sc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_sc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_sc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_sc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_sc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

   /* Chinese (Traditional) */
    mnemonic_to_seed(test_mnemonic_12_tc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_tc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_tc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_tc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_tc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_tc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_tc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_tc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_tc, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_tc),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

   /* French */
    mnemonic_to_seed(test_mnemonic_12_fra, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_fra),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_fra, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_fra),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_fra, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_fra),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_fra, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_fra),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_fra, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_fra),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);


   /* Italian */
    mnemonic_to_seed(test_mnemonic_12_ita, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_ita),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_ita, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_ita),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_ita, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_ita),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_ita, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_ita),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_ita, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_ita),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

   /* Korean */
    mnemonic_to_seed(test_mnemonic_12_kor, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_kor),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_kor, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_kor),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_kor, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_kor),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_kor, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_kor),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_kor, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_kor),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);


       /* Czech */
    mnemonic_to_seed(test_mnemonic_12_cze, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_cze),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_cze, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_cze),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_cze, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_cze),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_cze, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_cze),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_cze, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_cze),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);


    /* Portuguese */
    mnemonic_to_seed(test_mnemonic_12_por, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_12_por),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_15_por, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_15_por),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_18_por, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_18_por),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_21_por, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_21_por),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);

    mnemonic_to_seed(test_mnemonic_24_por, "", seed, 0);
    memcpy_safe(seed_test,
           utils_hex_to_uint8(test_seed_24_por),
           64);
    assert(memcmp(seed, seed_test, 64) == 0);
}
