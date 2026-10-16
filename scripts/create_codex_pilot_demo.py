"""Create a new, dependency-free business project for the Codex pilot.

This is a starting project for normal development, not a replay of the model
benchmark.  It never edits an existing directory or installs host settings.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from textwrap import dedent


def _source(value: str) -> str:
    return dedent(value).lstrip("\n")


FILES = {
    ".gitignore": "__pycache__/\n*.py[cod]\n.pytest_cache/\n",
    "orderdesk/__init__.py": '"""A small local order service used for normal development in Codex."""\n',
    "orderdesk/models.py": _source('''
        from dataclasses import dataclass


        @dataclass(frozen=True)
        class Order:
            id: str
            owner_id: str
            status: str
            total_cents: int
            notes: str
            receipt: str
    '''),
    "orderdesk/repository.py": _source('''
        from collections.abc import Iterable

        from .models import Order


        class OrderRepository:
            def __init__(self, orders: Iterable[Order]):
                self._orders = tuple(orders)

            def list_for_owner(self, owner_id: str) -> tuple[Order, ...]:
                return tuple(order for order in self._orders if order.owner_id == owner_id)

            def find_for_owner(self, owner_id: str, order_id: str) -> Order | None:
                return next((order for order in self._orders
                             if order.id == order_id and order.owner_id == owner_id), None)
    '''),
    "orderdesk/service.py": _source('''
        from .repository import OrderRepository


        class OrderService:
            def __init__(self, repository: OrderRepository):
                self.repository = repository

            @staticmethod
            def _owner(owner_id: str) -> str:
                if not isinstance(owner_id, str) or not owner_id.strip():
                    raise ValueError("A current user is required")
                return owner_id

            def list_orders(self, owner_id: str) -> list[dict]:
                owner_id = self._owner(owner_id)
                return [dict(id=order.id, status=order.status, total_cents=order.total_cents)
                        for order in self.repository.list_for_owner(owner_id)]

            def get_order(self, owner_id: str, order_id: str) -> dict | None:
                order = self.repository.find_for_owner(self._owner(owner_id), order_id)
                if order is None:
                    return None
                return dict(id=order.id, status=order.status, total_cents=order.total_cents)

            def get_receipt(self, owner_id: str, order_id: str) -> dict | None:
                order = self.repository.find_for_owner(self._owner(owner_id), order_id)
                if order is None:
                    return None
                return dict(order_id=order.id, receipt=order.receipt,
                            total_cents=order.total_cents)
    '''),
    "orderdesk/sample_data.py": _source('''
        from .models import Order
        from .repository import OrderRepository
        from .service import OrderService


        def sample_service() -> OrderService:
            return OrderService(OrderRepository([
                Order("order-1001", "alice", "paid", 12500, "Deliver in the morning", "R-1001"),
                Order("order-1002", "alice", "pending", 3200, "Gift wrapping", "R-1002"),
                Order("order-1003", "alice", "paid", 6800, "Leave at reception", "R-1003"),
                Order("order-2001", "bob", "paid", 9900, "Bob's private note", "R-2001"),
            ]))
    '''),
    "orderdesk/__main__.py": _source('''
        import argparse
        import json

        from .sample_data import sample_service


        def main() -> int:
            parser = argparse.ArgumentParser(description="Local order desk")
            commands = parser.add_subparsers(dest="command", required=True)
            for name in ("list", "details", "receipt"):
                command = commands.add_parser(name)
                command.add_argument("--user", required=True,
                                     help="Local demo user; production authentication is out of scope")
                if name != "list":
                    command.add_argument("--order", required=True)
            args = parser.parse_args()
            service = sample_service()
            if args.command == "list":
                result = service.list_orders(args.user)
            elif args.command == "details":
                result = service.get_order(args.user, args.order)
            else:
                result = service.get_receipt(args.user, args.order)
            if result is None:
                print(json.dumps({"error": "Order not found"}))
                return 1
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0


        if __name__ == "__main__":
            raise SystemExit(main())
    '''),
    "tests/test_orders.py": _source('''
        import unittest

        from orderdesk.sample_data import sample_service


        class OrderServiceTests(unittest.TestCase):
            def setUp(self):
                self.service = sample_service()

            def test_list_contains_only_current_users_orders(self):
                orders = self.service.list_orders("alice")
                self.assertEqual([order["id"] for order in orders],
                                 ["order-1001", "order-1002", "order-1003"])

            def test_bob_has_a_separate_list(self):
                self.assertEqual([order["id"] for order in self.service.list_orders("bob")],
                                 ["order-2001"])

            def test_unknown_user_has_no_orders(self):
                self.assertEqual(self.service.list_orders("nobody"), [])

            def test_owner_can_read_details(self):
                self.assertEqual(self.service.get_order("alice", "order-1001")["total_cents"],
                                 12500)

            def test_foreign_order_details_are_hidden(self):
                self.assertIsNone(self.service.get_order("alice", "order-2001"))

            def test_missing_order_is_hidden(self):
                self.assertIsNone(self.service.get_order("alice", "missing"))

            def test_owner_can_read_receipt(self):
                receipt = self.service.get_receipt("alice", "order-1001")
                self.assertEqual(receipt["receipt"], "R-1001")

            def test_foreign_order_receipt_is_hidden(self):
                self.assertIsNone(self.service.get_receipt("alice", "order-2001"))

            def test_current_user_is_required_for_every_operation(self):
                for operation in (lambda: self.service.list_orders(""),
                                  lambda: self.service.get_order(" ", "order-1001"),
                                  lambda: self.service.get_receipt("", "order-1001")):
                    with self.assertRaises(ValueError):
                        operation()


        if __name__ == "__main__":
            unittest.main()
    '''),
    "README.md": _source('''
        # Codex 实验版体验项目：订单服务

        这是供你在 Codex 中正常开发的小型业务项目。只有 Python 标准库，不需要
        pip 安装，不连接外部网络，也没有预先植入的漏洞。订单仓库、业务服务和
        命令行入口分开，现有订单列表、详情和收据查询均按当前用户限制数据。

        命令行的 `--user` 只是本地示例的用户上下文，不是生产认证方案。
        初始版本只实现基础查询；下面三个功能由开发 Agent 自行设计和实现，
        不使用固定补丁重放。实验版的连接和使用约定由安装程序单独配置。

        ## 先运行初始项目

        在项目目录运行以下命令；如果系统没有 `python`，使用安装器显示的 Python 路径。

        ```powershell
        python -m unittest discover -s tests -v
        python -m orderdesk list --user alice
        python -m orderdesk details --user alice --order order-1001
        python -m orderdesk receipt --user alice --order order-1001
        ```

        用 alice 查询 `order-2001` 应显示找不到订单，退出码为 1。

        ## 在 Codex 中体验

        打开这个项目，新建一次对话。先做任务一，再按自己的节奏发任务二、三。
        如果想观察同一次开发中安全分析与编码重叠，也可以把三段一起发送，要求
        按顺序实现。不用记工具名称；让 Agent 遵循项目的实验流程即可。

        ### 任务一：订单列表分页和筛选

        > 请实现订单列表按状态筛选和分页，并接到命令行。约定 page 从 1 开始，
        > page_size 为 1 到 100，参数不合法时给出清楚错误。筛选和分页后仍然
        > 只能返回当前用户的订单，顺序稳定。补充普通查询、边界参数和用户隔离
        > 的测试。按项目实验流程，在完成一批有意义的改动后启动后台安全分析，
        > 然后继续实现和验证，不要为了等后台结果停下开发；收尾时核对最终版本。

        ### 任务二：扩展订单详情

        > 请让订单详情返回备注，并按可选参数包含收据信息，命令行也支持这个
        > 参数。抽取适合复用的查询逻辑，保留列表、详情、收据各自的用户边界，
        > 外部用户订单和不存在的订单保持同样的找不到表现。补测试并运行。
        > 按项目实验流程分批处理，已有后台分析运行时继续开发；若又改了已检查
        > 的文件，结束时以最终文件重新核对，不要直接沿用旧结果。

        ### 任务三：订单 CSV 导出

        > 请增加当前用户订单 CSV 导出功能，并接到命令行，将内容输出到标准
        > 输出。复用状态筛选，但导出全部匹配订单，不受列表分页截断。使用标准
        > CSV 转义，考虑逗号、引号、换行和表格公式开头的文本。补充 CSV 内容、
        > 用户隔离和已有查询功能的回归测试。按项目实验流程在功能检查点启动
        > 后台安全分析，继续完成开发，最后核对最终版本并说明实际检查缺口。

        ## 看哪些体感

        - 一批改动后，是否启动后台分析，后续开发能否继续。
        - 改动同一文件后，旧结果是否明确过期；这不表示代码修改失败。
        - 收尾是否等待，等待多久；提示是否具体到文件、问题和原因。
        - 最终结论是否对应最后一次修改，而不是某个中途版本。
        - 实验过程记录的实际模型调用、token 和耗时是否可查看。

        没有发现问题也可能是正常结果。这里没有预设必须出现的漏洞，
        不应为了演示而添加不安全代码，也不要加等待来制造并行效果。
        检查不能保证没有漏洞；检查未完成时应如实说明范围。
    '''),
}


def create_demo(root: str | Path) -> Path:
    """Create the project at a new root and return its absolute path.

    Existing directories (including empty ones), files and links are rejected.
    No host configuration, Git state, model request or package installation is
    performed. The caller may add its own isolated pilot configuration later.
    """
    root = Path(root).expanduser().absolute()
    if os.path.lexists(root):
        raise FileExistsError(f"Refusing to overwrite an existing demo path: {root}")
    root.mkdir(parents=True, exist_ok=False)
    for relative, content in FILES.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="New project directory; must not already exist")
    args = parser.parse_args(argv)
    try:
        root = create_demo(args.root)
    except (FileExistsError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps({"root": str(root), "files": len(FILES), "git_initialized": False},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
