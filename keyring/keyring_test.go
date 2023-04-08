package keyring

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var keys = map[int]string{
	0: "520102ce528372e3edd5854530f45f13380d0051573b7f7588326e67e4da8a744ddd8626011b6488a61b7a8120ad515a8c1976be062aa450a1c65c069cf13811c6ca095550f16f078c5bb1d653716bdf02ec33ef66c38af3a92a1ea53d418c250f9d612fc95d5d12ef815d1b51db961cde9d3ae1b67a174522ee5f4b9902e358d8c5734e56eb361ee971c6be63e454900d72f0a6adf9e6d430b6e0aa015c6885efe960a34e3fecd7ede0379a1683a38647420a2a8a10b92618acc5ec0e80b6a1cbfb19af8ce2f5e365eaf81c52bd57183ae3a24505a4dea457b8ee151f1afa4e6e112ec534e9080a9d0fe806e5e2b897c65e81e0280d234f82179a82e2892d97850cfb80f9cce9219631ac9561d728b3425d7cbba103e670a1987e98651a34d9b6b3f0c99ca16ba8896eb60fd68810dbd32caf40ee00a0e867e26ab2b725b97434ab739cdf21ad49c940315ff0ed3d5ca6311edfed",
	1: "520105f9d63f08ef16289e61873bbe4b8ea2d9653c1c83c66e8e7da8b41815c98ce20c2601bc0af2589f1aacff226955a95d79ae087d413593d09054a66e41c3f2f309d80b705aed11cf89e72f00e59e4e1fc723567791678dc61102568af08d06864d06844bad5e5138be6c326c46a2a1c8d949b8bc3a054a1dee19bf1427970c1712cef8ec7c01f73ab189eb46d68f295ff25e5da7fa9c0631ade45eaf7e2a5a2b3d6dd75258a9d0f3dba8fbdbfb057f17eb4c91d1b0d4a4e7f26dfd68b8c30594eea739f6c3ae8178135b24da2687e08526b8822df14058f0c4405ade99214c1be9d0b74de4e0a84fb1be7dbcde54b5ec2208d03c32c3bd71fa856f84b768b31b1b9e9a401cf50049b0aec8eb7827f8ec1e58af1bfe50eb869469dce516106516be1e945085b5b56af16a4f04a44cd388aa989eff60696bc7f2ef60105c661bcf867c48b171160e2f5f87d2c15b871046e6029a",
	2: "5201043b46eeb7050e5d7965bdb8712ef104c5f56ddaffe0dec605aa4c3ea0e32414d9260149aa754235e0dc56cbbbcefdf64861a98bc503c35793d3199b3f3ac3d10a2f4660ab91477ab157cfa678272b71b76f072a5c70b30c6bff85588f78de82fa2b545f5e57f84217e73c90dbd67cd6b377ff9bb01bfe0eb7e518c63051e6b9fbcc93e2b5f094543f11ca2e8e53632cbd55b32a31ce4a6103b76cb8bd19c69f8808d65673f428790d0e9a5facd386b7435c483df177f9d0dabda2841e7802fc88353f1b725b55cc98f31cb79b2e09a8d2baa69372beab8941be8db31aeb71c08697cfb3e9ce4d77cde2de9b7f905c12e357ade4abd0cb45262dcbfc42d1978b255285353fa94a1a892b8e55b94a6a514f858d84887ef25ffe915e85cdca0b4a48552542220aeb0068410dad57ef8c0d3f47bbff5968b630475e27deef87e0116775424bed7c2b8fa6d89426d1031215372c0b",
	3: "5201045be67ef07fc84bb14649ab1a36353d329fdfdf936dc6a0534b6b03de06b903502601a81be73975a7d448a5016378fedf0db592acaf982a19e32cb57756f257faca39b067393b50d3cdfedcedc841dc92daebef939416fdc0a3f67a7b5ca8b99efdfbb84ccbd0d0f0e8430678e5ade06b5d6734880854e021ae3614c75e7c98b0db638e9e7787dfbe0089689254511e2d8273886ff3601f943dbaf71d0bb1942d77ba5638c87ce528ee3418864d54bfba47a7f5335695a6d58c1369f9cc4abbb2bd3965237eb29d16ab052c063dfa596d7b738136eeabba7ce796c6f465e7c7a57595516aaa074d3291b9d8879bd6d561793a03bcc5895891d6dcf3f6a51f0d754f02a22a809cb1465fc3a859e92d115e3f45aa9f39c970c646094f6d7ce52bfed77fefc40fb927dce5968f604229fa72c4e8bebf55bcdbbf8c5e37226e011e7a97743723c8834d41b7d4eb8a56c09d589ee3",
	4: "5201052d4f89e097ef0a7a551c732a1b737bb9c7c7f32d299b6f05448e8f619f5d7c1b2601a5e4b98832f8257ac9489085fdf7661b26e83e8f81c583aaf54312d7e27a1703f5f2c416d3f25dfc00d524ae6a031aba186bf9d3dff0a311e2aefae1c159bc6d4cb68c179437a2037e605caf80c67e8610a002d4666fc8386f242de3cd6d346ac2d167a35b1191c7c693d73a9a3ed87b0b131b5edc1ce33ea3404985b700fcbf79308f648c7bd17c8fce05f377097af0161316661653b515553590975e94405063d0082569bc98d9feb17fefeb81f988110174cd85430a6c80dadc10e2d903183983aaae75144328be75f92e1d52c75f14f31cde10d2443d409e2749966cf848c9a9bd0ae874794463b089de4ab20026acb70fddedb06ac4ba7da683b28ee21a224c01944dea14dcae05db9064316105b49d0a7138f24249069d04f01e010e09de70d74be0ad21cc4832e6d19f9d6e12",
}

var allKeys = joinKeys(keys)

func joinKeys(keys map[int]string) (s string) {
	for i := 0; i < len(keys); i++ {
		s += keys[i]
	}
	return
}

func TestSingleKeyUnmarshal(t *testing.T) {
	buf, err := hex.DecodeString(keys[0])
	assert.Nil(t, err)

	var key Key
	err = key.UnmarshalBinary(buf)
	assert.Nil(t, err)

	assert.Equal(t, "ARIA", key.Cipher)
	assert.Equal(t, byte(0xfb), key.Operand)
}

func TestMultiKeyUmmarshal(t *testing.T) {
	buf, err := hex.DecodeString(allKeys)
	assert.Nil(t, err)

	var keyring Keyring
	err = keyring.UnmarshalBinary(buf)
	assert.Nil(t, err)

	assert.Equal(t, "ARIA", keyring[0].Cipher)
	assert.Equal(t, "LEA", keyring[1].Cipher)
	assert.Equal(t, "SEED", keyring[2].Cipher)
	assert.Equal(t, "SEED", keyring[3].Cipher)
	assert.Equal(t, "LEA", keyring[4].Cipher)

	assert.Equal(t, byte(251), keyring[0].Operand)
	assert.Equal(t, byte(87), keyring[1].Operand)
	assert.Equal(t, byte(192), keyring[2].Operand)
	assert.Equal(t, byte(39), keyring[3].Operand)
	assert.Equal(t, byte(234), keyring[4].Operand)
}

func TestKeyringRegenerate(t *testing.T) {
	buf, err := hex.DecodeString(allKeys)
	assert.Nil(t, err)

	var keyring Keyring
	err = keyring.UnmarshalBinary(buf)
	assert.Nil(t, err)

	err = keyring.Regenerate()
	assert.Nil(t, err)

	assert.Equal(t, "ARIA", keyring[0].Cipher)
	assert.Equal(t, "LEA", keyring[1].Cipher)
	assert.Equal(t, "SEED", keyring[2].Cipher)
	assert.Equal(t, "SEED", keyring[3].Cipher)
	assert.Equal(t, "LEA", keyring[4].Cipher)

	assert.Equal(t, byte(251), keyring[0].Operand)
	assert.Equal(t, byte(87), keyring[1].Operand)
	assert.Equal(t, byte(192), keyring[2].Operand)
	assert.Equal(t, byte(39), keyring[3].Operand)
	assert.Equal(t, byte(234), keyring[4].Operand)
}
