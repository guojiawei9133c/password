package password

import (
	"testing"
)

func BenchmarkGenerate(b *testing.B) {
	b.Run("Normal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Generate("testpassword123")
		}
	})

	b.Run("Short", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Generate("pw")
		}
	})

	b.Run("Long", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Generate("a" + "verylong" + "verylong" + "verylong" + "verylong" + "verylong")
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	hash, _ := Generate("testpassword123")
	pw := Password(hash)

	b.Run("Correct", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = pw.Verify("testpassword123")
		}
	})

	b.Run("Wrong", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = pw.Verify("wrongpassword")
		}
	})

	b.Run("EmptyPlaintext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = pw.Verify("")
		}
	})
}

func BenchmarkParseHash(b *testing.B) {
	validHash := "$argon2id$v=19$m=65536,t=1,p=4$Lr27TtuSl/CAmXzbPLageA$bNemdbSgi3MtyvlnVoU1xnQ4eICpp4ObVprA1gbNDRU"

	b.Run("Valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _, _ = parseHash(validHash)
		}
	})

	b.Run("Invalid", func(b *testing.B) {
		invalidHash := "not_a_hash"
		for i := 0; i < b.N; i++ {
			_, _, _, _ = parseHash(invalidHash)
		}
	})
}
