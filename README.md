# GSB Bugfix Task
## 题面
升级内部任务调度模块后，反序列化任务payload出现代码执行风险：直接pickle.loads不受信输入、缺少类型白名单、未限制反序列化对象、未校验来源签名、未设置超时保护；scheduler/task_loader.py 是核心，tests/test_pickle_safe.py 15个红。要修的是：替换pickle为安全序列化、增加对象类型白名单、校验消息签名、限制反序列化耗时、拒绝外部不可信payload。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：其他
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
