package node

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/registry"
	"treecmd/internal/store"
)

// ---------- 结果索引（内存缓存，可重建；事实源是持有者 results 表） ----------

// indexEntry 索引里的一条记录：某条指令的结果在哪个节点、什么时候过期。
type indexEntry struct {
	OwnerPath string
	ExpireAt  time.Time
}

// resultIndex 结果索引的内存实现（指令 ID → 结果持有者路径），进程内缓存、可重建。
// 事实源是持有者本地的 results 表，这里只是为了少走网络。
type resultIndex struct {
	mu    sync.RWMutex
	items map[string]indexEntry
}

// newResultIndex 创建一个空的结果索引。
func newResultIndex() *resultIndex { return &resultIndex{items: map[string]indexEntry{}} }

// upsert 写入（或覆盖）一条索引项：指令 cmdID 的结果由 ownerPath 持有，expire 之后可被清理。
//
// 接收者 ri 是本节点的结果索引。
//
// 按 commandID 覆盖（不是"先删后插"，避免 NOT_FOUND 窗口）。
//
// 参数：
//
//	cmdID     — 指令 ID
//	ownerPath — 结果持有者的树内路径
//	expire    — 该索引项的过期时间
func (ri *resultIndex) upsert(cmdID, ownerPath string, expire time.Time) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	ri.items[cmdID] = indexEntry{OwnerPath: ownerPath, ExpireAt: expire}
}

// get 按指令 ID 读取一条索引项。
//
// 接收者 ri 是本节点的结果索引。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	indexEntry — 命中的记录；未命中时为零值
//	bool       — 是否命中
func (ri *resultIndex) get(cmdID string) (indexEntry, bool) {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	e, ok := ri.items[cmdID]
	return e, ok
}

// evictExpired 删掉索引里所有已过期的记录（ExpireAt 为零值表示不过期，保留）。
//
// 接收者 ri 是本节点的结果索引。
//
// 参数：
//
//	now — 用于判定的当前时间
func (ri *resultIndex) evictExpired(now time.Time) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	for k, v := range ri.items {
		if !v.ExpireAt.IsZero() && v.ExpireAt.Before(now) {
			delete(ri.items, k)
		}
	}
}

// len 返回当前索引项数量（供 /v1/tree 展示）。
//
// 接收者 ri 是本节点的结果索引。
func (ri *resultIndex) len() int {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return len(ri.items)
}

// ---------- 查询回程转发表（有界 TTL；**读不消费**，等回程结束才 drop） ----------

// routeEntry 回程转发表的一行：记下"这个查询请求是从哪来的"，回程时才知道往哪送。
type routeEntry struct {
	ReqID   string
	up      bool // true：来自父（回程往上走）；false：来自某子（回程往那个子走）
	childID string
	at      time.Time
}

// routeTable 查询回程转发表（reqID → 来向）：有界（TTL + 条数上限），读不消费，等回程结束才 drop。
type routeTable struct {
	mu  sync.Mutex
	m   map[string]routeEntry
	ttl time.Duration
	max int
}

// newRouteTable 创建一张回程转发表，非法的 TTL / 条数上限走默认值。
//
// 参数：
//
//	ttl — 表项存活时长；<=0 时用默认 10 秒
//	max — 表项条数上限；<=0 时用默认 1024
//
// 返回：
//
//	*routeTable — 可直接使用的转发表
func newRouteTable(ttl time.Duration, max int) *routeTable {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	if max <= 0 {
		max = 1024
	}
	return &routeTable{m: map[string]routeEntry{}, ttl: ttl, max: max}
}

// put 写入一条回程路由记录：先清理过期表项，条数到达上限时淘汰最旧的一条。
//
// 接收者 rt 是本节点的回程转发表。
//
// 参数：
//
//	e — 一条路由记录（reqID、来向 up、子节点 ID、写入时间）
func (rt *routeTable) put(e routeEntry) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	for id, x := range rt.m {
		if now.Sub(x.at) > rt.ttl {
			delete(rt.m, id)
		}
	}
	if len(rt.m) >= rt.max {
		oldest, first := "", true
		for id, x := range rt.m {
			if first || x.at.Before(rt.m[oldest].at) {
				oldest, first = id, false
			}
		}
		if oldest != "" {
			delete(rt.m, oldest)
		}
	}
	rt.m[e.ReqID] = e
}

// get 按 reqID 查这条回程该往哪走。
//
// 接收者 rt 是本节点的回程转发表。
//
// 只读不消费 —— `QueryResp` 之后可能还有一串 `QueryData` 要走同一条回程。
//
// 参数：
//
//	reqID — 查询请求 ID
//
// 返回：
//
//	routeEntry — 命中时的路由记录
//	bool       — 是否命中
func (rt *routeTable) get(reqID string) (routeEntry, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e, ok := rt.m[reqID]
	return e, ok
}

// drop 删除一条路由记录（回程已结束或校验失败、不再需要回程时调用）。
//
// 接收者 rt 是本节点的回程转发表。
//
// 参数：
//
//	reqID — 查询请求 ID
func (rt *routeTable) drop(reqID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.m, reqID)
}

// ---------- 入口侧的查询会话（含 QueryData 分片收齐与校验） ----------

// querySession 入口侧的查询会话：收集查询响应元数据与各个 QueryData 分片，
// 待收齐、校验、拼装后交给 Query 返回。
type querySession struct {
	reqID  string
	respCh chan *pb.QueryResp
	parts  map[int32][]byte
	total  int32
	final  bool
	pub    ed25519.PublicKey
	done   chan struct{}
	err    error
	once   sync.Once
}

// newQuerySession 新建一个查询会话并登记到本节点的会话表（键是 reqID），供回程数据找到入口。
//
// 接收者 n 是本节点实例（一个进程就是一个节点）。
//
// 参数：
//
//	reqID — 本次查询的请求 ID（由 Query 生成）
//
// 返回：
//
//	*querySession — 已登记、可接收回程数据的会话
func (n *Node) newQuerySession(reqID string) *querySession {
	s := &querySession{reqID: reqID, respCh: make(chan *pb.QueryResp, 1), done: make(chan struct{}), parts: map[int32][]byte{}}
	n.qmu.Lock()
	if n.querySess == nil {
		n.querySess = map[string]*querySession{}
	}
	n.querySess[reqID] = s
	n.qmu.Unlock()
	return s
}

// dropQuerySession 从会话表里移除一个查询会话（Query 收尾时 defer 调用）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	reqID — 要移除的查询请求 ID
func (n *Node) dropQuerySession(reqID string) {
	n.qmu.Lock()
	delete(n.querySess, reqID)
	n.qmu.Unlock()
}

// sessionFor 按 reqID 判断本节点是不是这个查询的入口，是则把会话取回来。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	reqID — 查询请求 ID
//
// 返回：
//
//	*querySession — 命中时的会话
//	bool          — 本节点是否为该查询的入口
func (n *Node) sessionFor(reqID string) (*querySession, bool) {
	n.qmu.Lock()
	defer n.qmu.Unlock()
	s, ok := n.querySess[reqID]
	return s, ok
}

// finish 结束会话：记下失败原因并关闭 done 通道通知等待者。
// sync.Once 保证只生效一次（元数据路径与末片路径都可能触发）。
//
// 接收者 s 是入口侧的查询会话。
//
// 参数：
//
//	err — 失败原因；成功传 nil
func (s *querySession) finish(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
	})
}

// addChunk 收下一片结果数据：首片带证书链（离线验链取出公钥），逐片验 crc32 与 payload_sig，通过后按下标存起来。
//
// 接收者 s 是入口侧的查询会话。
//
// 参数：
//
//	d — 一片 QueryData（下标、总片数、压缩后的负载、crc32、签名，末片带 Final 标记）
//
// 返回：
//
//	error — 缺证书链 / 证书解析失败 / 公钥缺失 / crc32 不符 / 验签失败时返回
func (s *querySession) addChunk(d *pb.QueryData) error {
	if d.Index == 0 {
		if len(d.SignerCert) == 0 {
			return errors.New("查询结果分片缺少 signer_cert（首片必须携带）")
		}
		chain, err := parsePEMChain(d.SignerCert)
		if err != nil || len(chain) == 0 {
			return fmt.Errorf("signer_cert 解析失败: %v", err)
		}
		pub, ok := chain[0].PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("signer_cert 不是 ed25519")
		}
		s.pub = pub
	}
	if s.pub == nil {
		return errors.New("缺少 signer（首片未到）")
	}
	if crc32Of(d.Payload) != d.Crc32 {
		return errors.New("crc32 校验失败")
	}
	if !identity.Verify(s.pub, queryDataPayload(d), d.PayloadSig) {
		return errors.New("payload_sig 验签失败")
	}
	if _, dup := s.parts[d.Index]; !dup {
		cp := make([]byte, len(d.Payload))
		copy(cp, d.Payload)
		s.parts[d.Index] = cp
	}
	s.total = d.Total
	if d.Final {
		s.final = true
	}
	return nil
}

// assemble 分片收齐后按下标顺序逐片解压，再拼接成完整结果。
//
// 接收者 s 是入口侧的查询会话。
//
// 返回：
//
//	[]byte — 拼好的完整结果字节
//	error  — 缺末片 / 缺中间某片 / 解压失败时返回
func (s *querySession) assemble() ([]byte, error) {
	if !s.final {
		return nil, errors.New("分片未收齐（缺末片）")
	}
	out := make([]byte, 0)
	for i := int32(0); i < s.total; i++ {
		part, ok := s.parts[i]
		if !ok {
			return nil, fmt.Errorf("缺少第 %d 片", i)
		}
		zr, err := gzip.NewReader(bytes.NewReader(part))
		if err != nil {
			return nil, fmt.Errorf("第 %d 片解压失败: %w", i, err)
		}
		raw, err := io.ReadAll(io.LimitReader(zr, 32<<20))
		zr.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	return out, nil
}

// QueryOutcome 查询结果（元数据 + 结果字节）。
type QueryOutcome struct {
	Resp *pb.QueryResp
	Data []byte
}

// ---------- 查询流程 ----------

// handleQueryFromParent 处理父节点下发的查询请求（查询下行段的一跳）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	req — 父发来的查询请求（reqID、指令 ID、请求方签名）
//
// 返回：
//
//	error — 鉴权失败时回一条 VERIFY_FAILED；其余情况交给 routeQuery 决定
func (n *Node) handleQueryFromParent(req *pb.QueryReq) error {
	if err := n.checkReqAuth(req); err != nil {
		return n.forwardQueryResp(&pb.QueryResp{ReqId: req.ReqId, Status: "VERIFY_FAILED"})
	}
	return n.routeQuery(req)
}

// handleQueryFromChild 处理子节点上行的查询请求（查询上行段的一跳）：先记下"谁发给我"，再校验、路由。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cc  — 发来请求的子连接
//	req — 子发来的查询请求
//
// 返回：
//
//	error — 鉴权失败时回一条 VERIFY_FAILED；其余情况交给 routeQuery 决定
func (n *Node) handleQueryFromChild(cc *childConn, req *pb.QueryReq) error {
	n.routes.put(routeEntry{ReqID: req.ReqId, up: false, childID: cc.nodeID, at: time.Now()})
	if err := n.checkReqAuth(req); err != nil {
		return n.forwardQueryResp(&pb.QueryResp{ReqId: req.ReqId, Status: "VERIFY_FAILED"})
	}
	return n.routeQuery(req)
}

// routeQuery 查询路由三选一：本节点即结果持有者 → 直接回答；本节点是持有者的祖先 → 沿路径下行；否则继续上行。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	req — 走到本节点的查询请求
//
// 返回：
//
//	error — 转发或回答过程中的错误
func (n *Node) routeQuery(req *pb.QueryReq) error {
	if r, ok := n.localResult(req.CommandId); ok {
		return n.respondQuery(req, r)
	}
	if e, ok := n.index.get(req.CommandId); ok {
		ownerPath := e.OwnerPath
		if ownerPath == "" {
			ownerPath = n.SelfPath()
		}
		if registry.IsAncestor(n.SelfPath(), ownerPath) {
			if err := n.sendQueryDown(req, ownerPath); err == nil {
				return nil
			}
		}
	}
	if n.up != nil {
		return n.up.sendQueryReq(req)
	}
	return n.forwardQueryResp(&pb.QueryResp{ReqId: req.ReqId, Status: "NOT_FOUND"})
}

// sendQueryDown 从本节点沿 ownerPath 往下转发查询请求（路径前缀路由），并把下一跳记入回程转发表。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	req       — 查询请求
//	ownerPath — 结果持有者的树内路径
//
// 返回：
//
//	error — 本节点无下联 / 找不到下一跳时返回
func (n *Node) sendQueryDown(req *pb.QueryReq, ownerPath string) error {
	if n.hub == nil {
		return fmt.Errorf("NO_DOWNSTREAM")
	}
	remaining := registry.Remaining(ownerPath, n.SelfPath())
	seg := registry.FirstSegment(remaining)
	if seg == "" {
		return fmt.Errorf("NO_NEXT_HOP")
	}
	for _, c := range n.Reg.Snapshot() {
		segs := registry.Segments(c.Path)
		if c.NodeID == seg || (len(segs) > 0 && segs[len(segs)-1] == seg) {
			n.routes.put(routeEntry{ReqID: req.ReqId, up: false, childID: c.NodeID, at: time.Now()})
			return n.hub.sendQueryReqDown(c.NodeID, req)
		}
	}
	return fmt.Errorf("NO_NEXT_HOP")
}

// localResult 在本节点本地的 results 表里查一条指令结果。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	*pb.ResultRecord — 命中的结果记录
//	bool            — 本节点是否持有该结果
func (n *Node) localResult(cmdID string) (*pb.ResultRecord, bool) {
	var (
		r  *pb.ResultRecord
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		r, ok = tx.GetResult(cmdID)
		return nil
	})
	return r, ok
}

// respondQuery 持有者回答查询：≤256KB 内联返回；更大走 QueryData 分片；超 query_response_max_bytes 降级为对象存储引用。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	req — 查询请求
//	r   — 本节点持有的结果记录
//
// 返回：
//
//	error — 上传对象存储、回响应或发分片失败时返回
func (n *Node) respondQuery(req *pb.QueryReq, r *pb.ResultRecord) error {
	meta := &pb.QueryResp{
		ReqId: req.ReqId, Status: "OK", OwnerPath: n.SelfPath(),
		TraceSummary: r.TraceSummary, CommandStatus: r.Status,
	}
	switch {
	case len(r.Final) <= inlineResultLimit:
		meta.ResultInline = r.Final
		return n.forwardQueryResp(meta)
	case int64(len(r.Final)) > int64(n.C().Query.QueryResponseMaxBytes):
		// 超过"入口愿意为一个查询最多缓存多少字节"→ 强制降级为对象存储引用（绝不静默截断）
		ref, hash, err := n.Obj.Put(r.Final)
		if err != nil {
			return err
		}
		meta.ResultRef = &pb.ResultRef{Kind: pb.ResultRefKind_RESULT_REF_OBJECT_STORE, Ref: ref, Hash: hash, Size: int64(len(r.Final))}
		return n.forwardQueryResp(meta)
	default:
		meta.HasData = true
		if err := n.forwardQueryResp(meta); err != nil {
			return err
		}
		return n.sendQueryData(req.ReqId, r.Final)
	}
}

// sendQueryData 把结果字节分片回传：逐片 gzip + crc32 + 持有者身份签名，首片额外带证书链。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	reqID — 查询请求 ID（回程转发表的键）
//	final — 待回传的完整结果字节
//
// 返回：
//
//	error — 分片数超上限 / 压缩失败 / 回程转发失败时返回
func (n *Node) sendQueryData(reqID string, final []byte) error {
	chunkSize := int(n.C().Command.ChunkSize)
	total := int32((len(final) + chunkSize - 1) / chunkSize)
	if total == 0 {
		total = 1
	}
	if total > n.C().Command.MaxChunkTotal {
		return fmt.Errorf("ERR_QUERY_RESULT_TOO_LARGE")
	}
	var certPEM []byte
	for _, c := range n.Id().Chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	for i := int32(0); i < total; i++ {
		lo := int(i) * chunkSize
		hi := lo + chunkSize
		if hi > len(final) {
			hi = len(final)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(final[lo:hi]); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		payload := buf.Bytes()
		d := &pb.QueryData{
			ReqId: reqID, Index: i, Total: total, Payload: payload,
			Crc32: crc32Of(payload), Final: i == total-1,
		}
		d.PayloadSig = identity.Sign(n.Id().Key, queryDataPayload(d))
		if i == 0 {
			d.SignerCert = certPEM
		}
		if err := n.forwardQueryData(d); err != nil {
			return err
		}
	}
	return nil
}

// queryDataPayload 用 canonical 编码把一片结果的关键信息串起来，作为签名与验签共用的待签字节。
//
// 参数：
//
//	d — 一片 QueryData
//
// 返回：
//
//	[]byte — 编码后的字节串
func queryDataPayload(d *pb.QueryData) []byte {
	w := canon.NewWriter()
	w.Str(d.ReqId).I64(int64(d.Index)).I64(int64(d.Total)).U64(uint64(d.Crc32)).Bytes(d.Payload)
	return w.Out()
}

// forwardQueryResp 查询响应的回程：本节点是入口就交给会话；否则按 reqID 查转发表，原路回上一跳。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	resp — 要回传的查询响应元数据（小结果 / 引用 / 错误时，它就代表全部内容）
//
// 返回：
//
//	error — 向上一跳或下一跳发送失败时返回
func (n *Node) forwardQueryResp(resp *pb.QueryResp) error {
	if s, ok := n.sessionFor(resp.ReqId); ok {
		select {
		case s.respCh <- resp:
		default:
		}
		if !resp.HasData { // 小结果 / 引用 / 错误：元数据即全部内容
			if resp.Status == "OK" && resp.OwnerPath != "" {
				n.index.upsert(resp.ReqId, resp.OwnerPath, time.Now().Add(n.resultsRetention()))
			}
			s.finish(nil)
		}
		return nil
	}
	e, ok := n.routes.get(resp.ReqId)
	if !ok {
		return nil
	}
	if !resp.HasData {
		n.routes.drop(resp.ReqId)
	}
	if e.up {
		if n.up != nil {
			return n.up.sendQueryResp(resp)
		}
		return nil
	}
	if n.hub != nil {
		return n.hub.sendQueryRespDown(e.childID, resp)
	}
	return nil
}

// forwardQueryData 结果分片的回程：与 QueryResp 走同一条路（转发表读不消费，末片才 drop）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	d — 一片结果数据
//
// 返回：
//
//	error — 转发失败时返回；入口侧校验失败时返回 nil（错误记在会话上，不伪装成 NOT_FOUND）
func (n *Node) forwardQueryData(d *pb.QueryData) error {
	if s, ok := n.sessionFor(d.ReqId); ok {
		if err := s.addChunk(d); err != nil {
			s.finish(err)
			return nil // 校验失败不回传分片，让入口报"校验失败"（不能伪装成 NOT_FOUND）
		}
		if d.Final {
			s.finish(nil)
		}
		return nil
	}
	e, ok := n.routes.get(d.ReqId)
	if !ok {
		return nil
	}
	if d.Final {
		n.routes.drop(d.ReqId)
	}
	if e.up {
		if n.up != nil {
			return n.up.sendQueryData(d)
		}
		return nil
	}
	if n.hub != nil {
		return n.hub.sendQueryDataDown(e.childID, d)
	}
	return nil
}

// Query 统一查询入口（只供有对外端点的节点调用）。
//
// 接收者 n 是本节点实例。
//
// 先上行找索引（最坏到根），再从"确定为持有者祖先"的一跳下行；结果沿转发表反向原路回。
//
// 参数：
//
//	cmdID — 指令 ID（ULID 字符串，提交时由发起节点生成）
//
// 返回：
//
//	*QueryOutcome — 结果内容 + 持有者路径；大结果会自动分片
//	error         — 分片超时未收齐 / 结果校验失败时返回；查不到结果时返回 Status=NOT_FOUND 而不返回 error
func (n *Node) Query(cmdID string) (*QueryOutcome, error) {
	if r, ok := n.localResult(cmdID); ok {
		resp := &pb.QueryResp{Status: "OK", OwnerPath: n.SelfPath(), CommandStatus: r.Status, TraceSummary: r.TraceSummary}
		if len(r.Final) <= inlineResultLimit {
			resp.ResultInline = r.Final
		} else {
			resp.ResultRef = &pb.ResultRef{Kind: pb.ResultRefKind_RESULT_REF_OBJECT_STORE,
				Hash: canon.DigestBytes(r.Final), Size: int64(len(r.Final))}
		}
		return &QueryOutcome{Resp: resp, Data: r.Final}, nil
	}

	reqID := fmt.Sprintf("q-%s-%d", shortID(n.C().Node.ID), time.Now().UnixNano())
	sess := n.newQuerySession(reqID)
	defer n.dropQuerySession(reqID)
	req := &pb.QueryReq{ReqId: reqID, CommandId: cmdID}
	req.ReqAuth = n.makeReqAuth(cmdID, false, 2)

	sent := false
	if e, ok := n.index.get(cmdID); ok && registry.IsAncestor(n.SelfPath(), e.OwnerPath) {
		if err := n.sendQueryDown(req, e.OwnerPath); err == nil {
			sent = true
		}
	}
	if !sent {
		if n.up == nil {
			return &QueryOutcome{Resp: &pb.QueryResp{Status: "NOT_FOUND"}}, nil
		}
		if err := n.up.sendQueryReq(req); err != nil {
			return &QueryOutcome{Resp: &pb.QueryResp{Status: "NOT_FOUND"}}, nil
		}
	}

	var resp *pb.QueryResp
	select {
	case resp = <-sess.respCh:
	case <-time.After(5 * time.Second):
		return &QueryOutcome{Resp: &pb.QueryResp{Status: "NOT_FOUND"}}, nil
	}
	out := &QueryOutcome{Resp: resp}
	if resp.Status != "OK" || !resp.HasData {
		out.Data = resp.ResultInline
		return out, nil
	}
	select {
	case <-sess.done:
	case <-time.After(20 * time.Second):
		return nil, errors.New("查询结果分片超时未收齐")
	}
	if sess.err != nil {
		return nil, fmt.Errorf("查询结果校验失败: %w", sess.err)
	}
	data, err := sess.assemble()
	if err != nil {
		return nil, err
	}
	out.Data = data
	return out, nil
}

// allowedQueryViewer 结果查询鉴权：query_viewers 为空（默认）即放行全体合法树成员；非空才收紧。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	viewerID — 发起查询的节点 ID
//
// 返回：
//
//	bool — 是否允许该节点查看结果
func (n *Node) allowedQueryViewer(viewerID string) bool {
	v := n.C().Query.QueryViewers
	if len(v) == 0 {
		return true
	}
	for _, x := range v {
		if x == "*" || x == viewerID {
			return true
		}
	}
	return false
}

// allowedHealthViewer 健康查询鉴权：默认严格（直接父 + root）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	viewerID — 发起健康查询的节点 ID
//
// 返回：
//
//	bool — 是否允许该节点查询本节点健康状态
func (n *Node) allowedHealthViewer(viewerID string) bool {
	v := n.C().Security.HealthViewers
	if len(v) == 0 {
		for _, p := range n.C().Parents {
			if p.ID == viewerID {
				return true
			}
		}
		// 默认白名单 = 直接父 + root。root 的身份按"在我祖先链上"判定
		//（根的路径是 "/"，从路径取不出它的 NodeID，故用 RegisterAck 下发的 ancestor_ids）。
		return n.isAncestorID(viewerID)
	}
	for _, x := range v {
		if x == "*" || x == viewerID {
			return true
		}
	}
	return false
}

// allowedOrigin 发起指令鉴权：trusted_origins 为空即放行全体合法成员。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	originID — 指令发起节点的 ID
//
// 返回：
//
//	bool — 是否允许该节点向本节点发起指令
func (n *Node) allowedOrigin(originID string) bool {
	v := n.C().Security.TrustedOrigins
	if len(v) == 0 {
		return true
	}
	for _, x := range v {
		if x == "*" || x == originID {
			return true
		}
	}
	return false
}

// TreeSnapshot 生成本节点视角的拓扑快照，供 HTTP /v1/tree 展示。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	map[string]any — 本节点信息、直接子节点列表（按 path 排序）、在线子连接数、索引条数、对象存储目录
func (n *Node) TreeSnapshot() map[string]any {
	children := []map[string]any{}
	if n.hub != nil {
		mine := n.Build()
		for _, c := range n.Reg.Snapshot() {
			_, online := n.hub.conn(c.NodeID)
			children = append(children, map[string]any{
				"node_id": c.NodeID, "path": c.Path, "online": online,
				"node_name": c.Name, "node_remark": c.Remark,
				// 这个子跑的是哪份镜像 + 是不是还没跟上（父端一眼看出收敛进度）
				"build_hash":     shortHash(c.BuildHash),
				"build_mismatch": c.BuildHash != "" && mine.Known() && c.BuildHash != mine.Hash,
				// 这个子**自己的 CA 证书**还剩几天（0 = 它不是中继、没有 CA 证书）。
				// CA 证书过期会让它下次启动直接起不来，所以值得在拓扑里一眼看见。
				"ca_not_after_days": c.CADays,
			})
		}
	}
	sort.SliceStable(children, func(i, j int) bool {
		return children[i]["path"].(string) < children[j]["path"].(string)
	})
	return map[string]any{
		"node_id": n.C().Node.ID, "path": n.SelfPath(), "role": string(n.Role()),
		"node_name": n.C().Node.Name, "node_remark": n.C().Node.Remark,
		"listen": n.C().Node.Listen, "children": children,
		"conn_children": n.childOnline(), "index_entries": n.index.len(),
		"object_store": n.Obj.Dir(),
		// 本节点自己那份镜像：与每个子上报的 build_hash 比一比，就知道谁还没收敛
		"build_hash":    n.Build().Short(),
		"build_version": n.Build().Version,
		// 本节点自己的证书剩余天数：身份证书与 CA 证书分开给。
		// 两个都是启动强校验的硬门槛（任一过期 → REFUSE TO START），所以要一起看得见。
		"cert_not_after_days": certNotAfterDays(n.Id()),
		"ca_not_after_days":   caNotAfterDays(n.Id()),
		"lagging_children":    n.laggingChildren(),
		// 镜像分片缓存的进度：本节点从父那里"收到并验证过"的片到哪了。
		// 它>0 而 lagging_children 还没归零，就说明"边收边转发"的流水线正在跑。
		"piece_store":         n.pieceProgress(),
		"selfupdate_enabled":  n.C().SelfUpdate.SelfUpdateEnabled(),
		"selfupdate_serve":    n.C().SelfUpdate.ServingChildren(),
		"selfupdate_enforced": n.C().SelfUpdate.EnforceSync(),
	}
}
