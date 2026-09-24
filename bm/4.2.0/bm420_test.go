package bmp420

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"xvertile/akamai-bmp/dm"
)

func TestAzulSensorLayoutAndIntegrity(t *testing.T) {
	devices, err := dm.LoadDevicesFromFile("../../server/db/devices.json")
	if err != nil || len(devices) == 0 {
		t.Fatalf("load devices: %v", err)
	}
	profile := DeviceProfileFromDM(devices[0], "pt_BR")
	profile.AppSignatureSHA1 = "bb40c0885cba78e617b4c484de534fc0b5dd3c59"
	g, err := NewGenerator(profile, "br.com.voeazul", "7.4.1", 4141,
		"https://b2c-api.voeazul.com.br")
	if err != nil {
		t.Fatal(err)
	}
	sensor := g.Generate(GenerateOpts{DeviceID: profile.AndroidID})
	parts := strings.Split(sensor, "$")
	if len(parts) != 7 || !strings.HasPrefix(parts[0], "6,a,") {
		t.Fatalf("unexpected header shape: %d parts", len(parts))
	}
	if !strings.HasSuffix(parts[6], "&&&4.2.0") {
		t.Fatal("metadata lacks sensor version 4.2.0")
	}
	packet, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(packet) < 16+32+16 {
		t.Fatal("invalid encrypted payload")
	}
	iv, ciphertext, tag := packet[:16], packet[16:len(packet)-32], packet[len(packet)-32:]
	mac := hmac.New(sha256.New, g.Ctx.HMACKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		t.Fatal("payload HMAC mismatch")
	}
	block, err := aes.NewCipher(g.Ctx.AESKey)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize {
		t.Fatal("invalid padding")
	}
	plain = plain[:len(plain)-pad]
	s := string(plain)
	if !strings.HasPrefix(s, "4.2.0") || !strings.Contains(s, "br.com.voeazul") {
		t.Fatal("sensor version or app identity missing")
	}
	last := 0
	for _, field := range []string{
		"-90,", "-91,", "-70,", "-80,", "-121,", "-100,", "-101,",
		"-102,", "-103,", "-104,", "-108,", "-112,", "-117,", "-120,",
		"-144,", "-160,", "-142,", "-145,", "-161,", "-143,", "-150,",
		"-163,", "-165,", "-166,", "-171,", "-240,", "-172,", "-180,",
		"-115,",
	} {
		at := strings.Index(s[last:], Separator+field)
		if at < 0 {
			t.Fatalf("missing or out-of-order field %s", field)
		}
		last += at + len(Separator+field)
	}
}
