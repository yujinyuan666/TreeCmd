//go:build ignore

// ca-rotate 把某个节点目录里的 **CA 证书做旧**：NotBefore 往前挪、生命期缩短，
// 于是节点下次启动时这张证书就落在续签窗口里 —— 用来确定性地验证"CA 证书在线轮换"。
//
// 用法：
//
//	go run test/ca-rotate/main.go -dir test/demo/root -life 22h -age 20h
//
// **为什么必须做旧**：续签窗口的判据是"剩余有效期 < 生命期 1/3"（见 node/lifecycle.go 的
// needRenew）。刚签出来的证书剩余 = 全部生命期，永远不会在窗口里；而任何正常签发路径都
// 不会产出"NotBefore 在过去很久"的证书。所以只能由测试工具直接造一张。
//
// 它做两件事，且都用产品代码里的同一条路径，免得"测试夹具"与"真实签发"悄悄跑偏：
//
//  1. 用同一把 CA 私钥造一张**做旧的 CA 证书**（CN / 公钥 / keyUsage 逐项沿用旧的）——
//     这台机器上唯一需要"绕过产品代码"的地方，因为要做旧就只能直接写 NotBefore。
//  2. 用**新造的做旧 CA 证书**重签身份证书（走 identity.ReissueFor），保证启动强校验能过。
//
// 不动信任锚文件（certs/ca.crt 之类）：轮换验证的核心断言之一就是"程序不会去改它"。
package main

import (
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"treecmd/internal/identity"
)

func main() {
	dir := flag.String("dir", "", "节点目录（含 keys/ 与 certs/）")
	age := flag.Duration("age", 20*time.Hour, "做旧：CA 证书的 NotBefore 往前挪多久")
	life := flag.Duration("life", 22*time.Hour, "做旧：CA 证书的总生命期（NotAfter = NotBefore + life）")
	verifyAnchor := flag.String("verify-anchor", "", "只做校验：信任锚文件（可与 -verify-chain 一起用）")
	verifyChain := flag.String("verify-chain", "", "只做校验：待验证的证书链文件（PEM 串接，第一张是叶）")
	selftest := flag.Bool("selftest", false, "在内存里跑一遍 CA 轮换的完整机制（不动任何文件、不起任何进程）")
	flag.Parse()

	// 自检模式：不碰磁盘、不起进程，用产品代码里那条同一条路径走一遍
	// "造一张新 CA 证书 → 用它重签身份证书 → 用**旧的信任锚**验整条链"，
	// 并加一条负向用例证明放行范围是窄的。
	if *selftest {
		selftestRotation()
		return
	}

	// 校验模式：直接调用**产品代码里那个** ChainVerifier，把 Go 的原始报错打出来。
	// 排查"链为什么验不过"时靠它，而不是靠 openssl —— 两者的链构建策略并不相同
	// （openssl 会因为"中间证书自签"直接报 error 19，而本项目的 chainTrusts 明确把这种情况放行）。
	if *verifyAnchor != "" || *verifyChain != "" {
		verify(*verifyAnchor, *verifyChain)
		return
	}
	if *dir == "" {
		fatalf("必须给 -dir（或 -verify-anchor + -verify-chain）")
	}

	caKeyPath := filepath.Join(*dir, "keys", "ca")
	caCertPath := filepath.Join(*dir, "certs", "node.crt.ca")
	idCertPath := filepath.Join(*dir, "certs", "node.crt")

	caKey, err := identity.LoadIdentityKey(caKeyPath)
	if err != nil {
		fatalf("读 CA 私钥 %s: %v", caKeyPath, err)
	}
	oldCAChain, err := identity.LoadCertChainFile(caCertPath)
	if err != nil || len(oldCAChain) == 0 {
		fatalf("读 CA 证书链 %s: %v", caCertPath, err)
	}
	oldCA := oldCAChain[0]
	oldIDChain, err := identity.LoadCertChainFile(idCertPath)
	if err != nil || len(oldIDChain) == 0 {
		fatalf("读身份证书链 %s: %v", idCertPath, err)
	}

	// ---- ① 造一张做旧的 CA 证书：同一把密钥、同一 CN、同一 keyUsage ----
	now := time.Now()
	notBefore := now.Add(-*age)
	notAfter := notBefore.Add(*life)
	if !notAfter.After(now) {
		fatalf("算出来的 NotAfter 已经过期了（life %s 必须大于 age %s）", *life, *age)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fatalf("生成序列号: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		// **逐字节沿用旧的 Subject**：x509 认"同名"认的是这串 DER 字节，而同一个 CN/O
		// 由 openssl 与 Go 生成出来的编码并不相同（RDN 顺序不同）。用 pkix.Name 重建的话，
		// 造出来的就是"看起来同名、实际是另一个 subject"的证书 —— 测试会因此假失败
		// （产品代码里的 reissueWith 也是为此才必须传 RawSubject）。
		RawSubject:            oldCA.RawSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              oldCA.KeyUsage,
		URIs:                  oldCA.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if err != nil {
		fatalf("自签做旧的 CA 证书: %v", err)
	}
	newCA, err := x509.ParseCertificate(der)
	if err != nil {
		fatalf("解析新 CA 证书: %v", err)
	}
	if err := identity.WriteCertChainFile(caCertPath, []*x509.Certificate{newCA}); err != nil {
		fatalf("写回 CA 证书 %s: %v", caCertPath, err)
	}

	// ---- ② 用做旧的 CA 证书重签身份证书（走产品的重签路径）----
	owner := &identity.Identity{CAKey: caKey, CACert: newCA, CAChain: []*x509.Certificate{newCA}}
	pemBytes, err := identity.ReissueFor(oldIDChain[0], owner)
	if err != nil {
		fatalf("重签身份证书: %v", err)
	}
	idChain, err := identity.ParseChainPEM(pemBytes)
	if err != nil || len(idChain) == 0 {
		fatalf("解析重签后的身份证书链: %v", err)
	}
	if err := identity.WriteCertChainFile(idCertPath, idChain); err != nil {
		fatalf("写回身份证书 %s: %v", idCertPath, err)
	}

	fmt.Printf("CA 证书已做旧：%s\n", caCertPath)
	fmt.Printf("  CN            = %s（沿用）\n", oldCA.Subject.CommonName)
	fmt.Printf("  公钥是否不变  = %v\n", pubEqual(oldCA, newCA))
	fmt.Printf("  NotBefore     = %s\n", newCA.NotBefore.Format(time.RFC3339))
	fmt.Printf("  NotAfter      = %s（剩余 %s）\n", newCA.NotAfter.Format(time.RFC3339),
		time.Until(newCA.NotAfter).Round(time.Minute))
	fmt.Printf("  生命期        = %s ⇒ 续签窗口 = 剩余 < %s（现在落在窗口里）\n",
		newCA.NotAfter.Sub(newCA.NotBefore).Round(time.Minute),
		(newCA.NotAfter.Sub(newCA.NotBefore) / 3).Round(time.Minute))
	fmt.Printf("  旧指纹        = %x\n", identity.Fingerprint(oldCA)[:8])
	fmt.Printf("  新指纹        = %x\n", identity.Fingerprint(newCA)[:8])
	fmt.Printf("身份证书已用做旧的 CA 重签（NotAfter = %s）\n", idChain[0].NotAfter.Format(time.RFC3339))
}

// selftestRotation 在内存里跑一遍"CA 证书在线轮换"的完整机制，并验证四条不变量 + 一条负向。
//
// 为什么要这么一个自检：端到端脚本（ca-rotate.sh）要起两次树、还要靠 `rm` 清状态，
// 在受限环境里容易被拦；而这里要验的东西**完全可以在内存里判定**，且更精确：
//
//	A. 轮换后 CA 公钥不变（这就是"下级不用重新分发 trust/"的依据）；
//	B. 轮换后 CA 证书的 RawSubject 与旧证书**逐字节相同**（x509 认"同名"认的是这串字节）；
//	C. **用旧的那张信任锚**能验通"[新身份证书, 新 CA 证书]"这条链（这是最关键的一条）；
//	D. 负向：如果重签时用 pkix.Name 重建 Subject（而不是沿用 RawSubject），链**必须验不过**
//	   —— 证明 C 之所以通过是因为"同密钥"，而不是因为放行范围被开得太大。
func selftestRotation() {
	fail := 0
	check := func(ok bool, what string) {
		if ok {
			fmt.Printf("  ✓ %s\n", what)
		} else {
			fmt.Printf("  ✗ %s\n", what)
			fail++
		}
	}

	// 造一套根材料：CA 密钥对 + 自签 CA 证书 + 用它签的身份证书（都走产品代码）
	root, err := identity.GenerateRoot("0198f0c0-0000-7000-8000-0000de000001")
	if err != nil {
		fatalf("GenerateRoot: %v", err)
	}
	oldCA := root.CACert
	anchor := oldCA // 模拟"下级手里的 trust/ 副本"：就是**旧**那张根证书

	fmt.Println("① 造一份根材料，并记住旧 CA 证书（扮演下级手里的信任锚）")
	check(oldCA.IsCA && oldCA.KeyUsage&x509.KeyUsageCertSign != 0, "旧的 CA 证书是 CA 且可签发")

	fmt.Println("② 轮换 CA 证书（ReissueCAFor：同一把密钥、同一 subject）")
	newCA, _, err := identity.ReissueCAFor(oldCA, root)
	if err != nil {
		fatalf("ReissueCAFor: %v", err)
	}
	check(pubEqual(oldCA, newCA), "A. 公钥逐字节不变")
	check(string(oldCA.RawSubject) == string(newCA.RawSubject), "B. RawSubject 逐字节不变")
	check(!oldCA.Equal(newCA), "   （确实是一张**新**证书：serial/有效期不同）")

	fmt.Println("③ 用新 CA 证书重签身份证书，再用**旧信任锚**验这条链")
	owner := &identity.Identity{CAKey: root.CAKey, CACert: newCA, CAChain: []*x509.Certificate{newCA}}
	pemBytes, err := identity.ReissueFor(root.Cert, owner)
	if err != nil {
		fatalf("ReissueFor: %v", err)
	}
	chain, err := identity.ParseChainPEM(pemBytes)
	if err != nil {
		fatalf("ParseChainPEM: %v", err)
	}
	if err := identity.ChainToAnchor(chain, []*x509.Certificate{anchor}, 0); err != nil {
		check(false, "C. 旧锚能验通新链（错误："+err.Error()+"）")
	} else {
		check(true, "C. 旧锚能验通「[新身份证书, 新 CA 证书]」—— 下级不用换 trust/ 就能继续握手")
	}
	// 身份证书链里带的必须就是新 CA 证书
	check(string(chain[len(chain)-1].Raw) == string(newCA.Raw), "   链末端就是刚轮换出来的那张 CA 证书")

	fmt.Println("④ 负向：同 subject 但**不同密钥**的自签 CA 证书 → 必须被拒")
	// 这一条是"放行范围到底有多宽"的关键：④ 要求的是**公钥逐字节相同**，
	// 而不是"subject 看起来一样" —— 否则任何人都能造一张同名不同密钥的自签证书混进来。
	_, evilKey, err := identity.GenerateKeyPair()
	if err != nil {
		fatalf("GenerateKeyPair: %v", err)
	}
	evilSN, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fatalf("生成序列号: %v", err)
	}
	now := time.Now()
	evilTmpl := &x509.Certificate{
		SerialNumber:          evilSN,
		RawSubject:            oldCA.RawSubject, // 同一个 subject
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
	}
	evilDER, err := x509.CreateCertificate(rand.Reader, evilTmpl, evilTmpl, evilKey.Public(), evilKey)
	if err != nil {
		fatalf("自签「伪造」的 CA 证书: %v", err)
	}
	evilCA, err := x509.ParseCertificate(evilDER)
	if err != nil {
		fatalf("解析伪造的 CA 证书: %v", err)
	}
	if string(evilCA.RawSubject) != string(oldCA.RawSubject) {
		check(false, "   前提不成立：伪造证书的 subject 与旧 CA 不同，这条负向没有意义")
	} else if err := identity.ChainToAnchor([]*x509.Certificate{evilCA}, []*x509.Certificate{anchor}, 0); err == nil {
		check(false, "D. 同 subject、不同密钥的自签 CA 被放行了（放行范围过宽！）")
	} else {
		check(true, "D. 同 subject、不同密钥的自签 CA 被拒 —— 放行的是「同密钥」而不是「同名」")
	}

	fmt.Println()
	if fail > 0 {
		fatalf("自检失败 %d 项", fail)
	}
	fmt.Println("自检全部通过：轮换只换证书、不换密钥，旧信任锚照旧可用。")
}

// pubEqual 报告两张证书的公钥是否逐字节相同（主键轮换与否就看它）。
func pubEqual(a, b *x509.Certificate) bool {
	ab, err1 := x509.MarshalPKIXPublicKey(a.PublicKey)
	bb, err2 := x509.MarshalPKIXPublicKey(b.PublicKey)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(ab) == string(bb)
}

// verify 用产品代码的 ChainVerifier 判一次链，并打印 Go 的原始报错。
//
// 它同时打印每张证书的 SubjectKeyId / AuthorityKeyId —— 排查"同一把密钥却链不通"时，
// 这两个字段是第一现场：证书的 SKI 由**生成方式**决定（Go 与 openssl 算出来的不一样），
// 而 Go 的链构建会先按 AKI→SKI 找签发者；SKI 对不上时它退回按 subject 匹配，
// 但"最后一张自签证书要接到的那个锚"如果与它 SKI 不同，就会得到
// "x509: certificate signed by unknown authority" 这种看起来完全不通的报错。
func verify(anchorPath, chainPath string) {
	if anchorPath == "" || chainPath == "" {
		fatalf("校验模式需要同时给 -verify-anchor 与 -verify-chain")
	}
	anchors, err := identity.LoadCertChainFile(anchorPath)
	if err != nil || len(anchors) == 0 {
		fatalf("读信任锚 %s: %v", anchorPath, err)
	}
	chain, err := identity.LoadCertChainFile(chainPath)
	if err != nil || len(chain) == 0 {
		fatalf("读证书链 %s: %v", chainPath, err)
	}
	fmt.Printf("信任锚 %s（%d 张）:\n", anchorPath, len(anchors))
	for i, c := range anchors {
		fmt.Printf("  [%d] CN=%s SKI=%x AKI=%x\n", i, c.Subject.CommonName, c.SubjectKeyId, c.AuthorityKeyId)
	}
	fmt.Printf("证书链 %s（%d 张）:\n", chainPath, len(chain))
	ders := make([][]byte, 0, len(chain))
	for i, c := range chain {
		fmt.Printf("  [%d] CN=%s SKI=%x AKI=%x\n", i, c.Subject.CommonName, c.SubjectKeyId, c.AuthorityKeyId)
		ders = append(ders, c.Raw)
	}
	verifier := identity.ChainVerifier(identity.NewPool(anchors...), "", 0)
	// 逐条打出"同密钥锚"兜底的四条判据，便于定位到底是哪一条不满足
	fmt.Println("---- chainTrustsSameKey 的四条判据 ----")
	all := append(append([]*x509.Certificate{}, chain...), anchors...)
	valid := true
	for i, c := range all {
		expired := time.Now().After(c.NotAfter)
		if expired {
			valid = false
		}
		fmt.Printf("  ① [%d] CN=%s NotAfter=%s 未过期=%v\n",
			i, c.Subject.CommonName, c.NotAfter.Format(time.RFC3339), !expired)
	}
	top := chain[len(chain)-1]
	fmt.Printf("  ② 末端自签（issuer==subject）= %v\n", string(top.RawIssuer) == string(top.RawSubject))
	for i := 0; i+1 < len(chain); i++ {
		issuerOK := string(chain[i].RawIssuer) == string(chain[i+1].RawSubject)
		var sigErr error
		if issuerOK {
			sigErr = chain[i].CheckSignatureFrom(chain[i+1])
		}
		fmt.Printf("  ③ 第 %d 跳验签：issuer 匹配=%v err=%v（parent IsCA=%v BCValid=%v KeyUsage=%v）\n",
			i, issuerOK, sigErr, chain[i+1].IsCA, chain[i+1].BasicConstraintsValid, chain[i+1].KeyUsage)
	}
	for _, r := range anchors {
		subjOK := string(r.RawSubject) == string(top.RawSubject)
		pkOK := pubEqual(r, top)
		fmt.Printf("  ④ 锚 CN=%s subject 相同=%v 公钥相同=%v\n", r.Subject.CommonName, subjOK, pkOK)
	}
	fmt.Printf("  （① 全部未过期=%v）\n", valid)
	fmt.Println("---- ChainVerifier 结果 ----")
	if err := verifier(ders, nil); err != nil {
		fmt.Printf("结果：不通过 —— %v\n", err)
		os.Exit(2)
	}
	fmt.Println("结果：通过（链能验到信任锚）")
}

// fatalf 打印错误并以非零码退出。
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ca-rotate: "+format+"\n", args...)
	os.Exit(1)
}
