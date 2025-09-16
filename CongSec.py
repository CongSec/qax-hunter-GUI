import requests
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import pandas as pd
import threading
import time
from tkinter import Menu
import random
import csv
import io
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

class HunterVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Hunter搜索结果可视化工具by CongSec~")
        self.root.geometry("1400x700")
        self.root.minsize(1200, 600)
        
        # 设置中文字体支持
        self.style = ttk.Style()
        self.style.configure("Treeview.Heading", font=("SimHei", 10, "bold"))
        self.style.configure("Treeview", font=("SimHei", 10), rowheight=25)
        
        # 当前页码和每页数量
        self.current_page = 1
        self.page_size = 10
        self.total_pages = 1
        self.total_results = 0
        
        # 存储所有数据
        self.all_data = []
        self.session = requests.Session()  # 创建会话对象，复用连接
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })
        
        # API配置
        self.api_key = "你的hunter key"
        self.search_query = 'protocol=="socks5"&&protocol.banner="No authentication"&&ip.country="CN"'  # 默认搜索条件
        self.is_web = 3  # 默认为全部资产
        self.start_time = "2025-07-23"
        self.end_time = "2025-08-21"
        
        # 控制请求速率的参数
        self.base_delay = 2  # 基础延迟时间（秒）
        self.max_retries = 5  # 最大重试次数
        
        # 创建消息队列用于线程间通信
        self.message_queue = Queue()
        
        # 定义所有可能的字段（包括表格显示的和API返回的其他字段）
        self.all_possible_fields = [
            "ip", "port", "protocol", "base_protocol", "country", "province", 
            "city", "isp", "as_org", "updated_at", "is_risk", "is_risk_protocol",
            "banner", "domain", "url", "web_title", "company", "vul_list", 
            "is_web", "os", "number", "header", "component", "status_code"
        ]
        
        # 表格显示的字段
        self.display_columns = [
            "ip", "port", "protocol", "base_protocol", "country", "province", 
            "city", "isp", "as_org", "updated_at", "is_risk", "is_risk_protocol",
            "banner", "domain", "url", "web_title"
        ]
        
        # 字段名称映射
        self.column_names = {
            "ip": "IP地址",
            "port": "端口",
            "protocol": "协议",
            "base_protocol": "基础协议",
            "country": "国家",
            "province": "省份",
            "city": "城市",
            "isp": "运营商",
            "as_org": "AS组织",
            "updated_at": "更新时间",
            "is_risk": "是否有风险",
            "is_risk_protocol": "协议是否有风险",
            "banner": "标识信息",
            "domain": "域名",
            "url": "URL地址",
            "web_title": "网站标题",
            "company": "公司",
            "vul_list": "漏洞列表",
            "is_web": "是否Web资产",
            "os": "操作系统",
            "number": "编号",
            "header": "HTTP头",
            "component": "组件",
            "status_code": "状态码"
        }
        
        # 创建界面
        self.create_widgets()
        
        # 启动消息处理循环
        self.process_messages()
        
        # 加载第一页数据
        self.load_data()
    
    def process_messages(self):
        """处理来自后台线程的消息"""
        try:
            while not self.message_queue.empty():
                message = self.message_queue.get_nowait()
                if message[0] == "update_status":
                    self.status_var.set(message[1])
                elif message[0] == "show_error":
                    messagebox.showerror(message[1], message[2])
                elif message[0] == "show_info":
                    messagebox.showinfo(message[1], message[2])
                elif message[0] == "update_table":
                    self.update_table()
                elif message[0] == "update_pagination":
                    self.update_pagination_info()
        except:
            pass
        
        # 每100毫秒检查一次消息
        self.root.after(100, self.process_messages)
    
    def create_widgets(self):
        # 创建顶部控制面板
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 搜索条件输入
        ttk.Label(control_frame, text="搜索条件:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(control_frame, width=50)
        self.search_entry.insert(0, self.search_query)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        # 资产类型选择
        ttk.Label(control_frame, text="资产类型:").pack(side=tk.LEFT, padx=5)
        self.web_type = tk.StringVar(value="3")
        web_type_frame = ttk.Frame(control_frame)
        ttk.Radiobutton(web_type_frame, text="Web资产", variable=self.web_type, value="1").pack(side=tk.LEFT)
        ttk.Radiobutton(web_type_frame, text="非Web资产", variable=self.web_type, value="2").pack(side=tk.LEFT)
        ttk.Radiobutton(web_type_frame, text="全部", variable=self.web_type, value="3").pack(side=tk.LEFT)
        web_type_frame.pack(side=tk.LEFT, padx=5)
        
        # 每页数量选择
        ttk.Label(control_frame, text="每页数量:").pack(side=tk.LEFT, padx=5)
        self.page_size_var = tk.StringVar(value="10")
        page_size_combo = ttk.Combobox(control_frame, textvariable=self.page_size_var, values=["10", "20", "50", "100"], width=5)
        page_size_combo.pack(side=tk.LEFT, padx=5)
        
        # 搜索按钮
        search_btn = ttk.Button(control_frame, text="搜索", command=self.on_search)
        search_btn.pack(side=tk.LEFT, padx=5)
        
        # 导出按钮
        export_btn = ttk.Button(control_frame, text="导出数据", command=self.export_data)
        export_btn.pack(side=tk.RIGHT, padx=5)
        
        # 创建数据表格
        table_frame = ttk.Frame(self.root, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 滚动条
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
        scrollbar_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        
        # 表格
        self.tree = ttk.Treeview(
            table_frame,
            columns=self.display_columns,
            show="headings",
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )
        
        # 设置列标题和宽度
        for col in self.display_columns:
            self.tree.heading(col, text=self.column_names[col])
            self.tree.column(col, width=100)
        
        # 调整部分列宽
        self.tree.column("ip", width=130)
        self.tree.column("as_org", width=150)
        self.tree.column("protocol", width=80)
        self.tree.column("banner", width=120)
        self.tree.column("url", width=150)
        self.tree.column("web_title", width=150)
        
        # 绑定右键菜单 - 表头和单元格都可触发
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="复制单元格", command=self.copy_cell_value)
        self.context_menu.add_command(label="复制整行", command=self.copy_row_values)
        self.context_menu.add_command(label="复制整列", command=self.copy_column_values)
        
        # 放置滚动条和表格
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar_x.config(command=self.tree.xview)
        scrollbar_y.config(command=self.tree.yview)
        
        # 创建分页控制
        pagination_frame = ttk.Frame(self.root, padding="10")
        pagination_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.page_info = ttk.Label(pagination_frame, text="第 1 页，共 0 页，总计 0 条数据")
        self.page_info.pack(side=tk.LEFT, padx=10)
        
        # 页码输入框
        ttk.Label(pagination_frame, text="跳至:").pack(side=tk.LEFT, padx=5)
        self.page_entry = ttk.Entry(pagination_frame, width=5)
        self.page_entry.insert(0, "1")
        self.page_entry.pack(side=tk.LEFT, padx=5)
        go_btn = ttk.Button(pagination_frame, text="前往", command=self.go_to_page)
        go_btn.pack(side=tk.LEFT, padx=5)
        
        # 翻页按钮
        self.prev_btn = ttk.Button(pagination_frame, text="上一页", command=self.prev_page)
        self.prev_btn.pack(side=tk.RIGHT, padx=5)
        
        self.next_btn = ttk.Button(pagination_frame, text="下一页", command=self.next_page)
        self.next_btn.pack(side=tk.RIGHT, padx=5)
        
        # 创建状态框
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def show_context_menu(self, event):
        """显示右键菜单，支持表头和单元格"""
        region = self.tree.identify_region(event.x, event.y)
        if region in ("cell", "heading"):
            # 获取选中的行和列
            self.selected_row = self.tree.identify_row(event.y)
            self.selected_col = self.tree.identify_column(event.x)
            
            # 如果点击的是表头，选中整列
            if region == "heading":
                self.tree.selection_remove(*self.tree.selection())  # 清除行选择
            
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_cell_value(self):
        """复制选中单元格的值"""
        try:
            if not hasattr(self, 'selected_row') or not hasattr(self, 'selected_col') or not self.selected_row:
                raise IndexError
            
            # 转换列标识符为索引
            col_index = int(self.selected_col.replace('#', '')) - 1
            cell_value = self.tree.item(self.selected_row, "values")[col_index]
            
            # 复制到剪贴板
            self.root.clipboard_clear()
            self.root.clipboard_append(str(cell_value))
            self.status_var.set(f"已复制单元格内容: {str(cell_value)[:30]}...")
        except (IndexError, ValueError):
            self.status_var.set("复制失败，请确保已选中有效单元格")
    
    def copy_row_values(self):
        """复制选中行的所有值"""
        try:
            if not hasattr(self, 'selected_row') or not self.selected_row:
                raise IndexError
            
            row_values = self.tree.item(self.selected_row, "values")
            
            # 将列名和值组合
            row_data = []
            for i, value in enumerate(row_values):
                if value:  # 只复制有值的字段
                    row_data.append(f"{self.column_names[self.display_columns[i]]}: {value}")
            
            row_text = "\n".join(row_data)
            
            # 复制到剪贴板
            self.root.clipboard_clear()
            self.root.clipboard_append(row_text)
            self.status_var.set(f"已复制整行数据，共{len(row_data)}个字段")
        except IndexError:
            self.status_var.set("复制失败，请确保已选中有效行")
    
    def copy_column_values(self):
        """复制整列数据"""
        try:
            if not hasattr(self, 'selected_col'):
                raise IndexError
            
            # 转换列标识符为索引
            col_index = int(self.selected_col.replace('#', '')) - 1
            col_name = self.column_names[self.display_columns[col_index]]
            
            # 收集整列数据
            column_data = [col_name]  # 第一行为列名
            for item in self.tree.get_children():
                cell_value = self.tree.item(item, "values")[col_index]
                column_data.append(str(cell_value))
            
            # 连接成文本
            column_text = "\n".join(column_data)
            
            # 复制到剪贴板
            self.root.clipboard_clear()
            self.root.clipboard_append(column_text)
            self.status_var.set(f"已复制整列数据: {col_name}，共{len(column_data)-1}条记录")
        except (IndexError, ValueError):
            self.status_var.set("复制失败，请确保已选中有效列")
    
    def encode_search_query(self, query):
        """将搜索条件编码为base64"""
        return base64.b64encode(query.encode()).decode()
    
    def build_url(self, page):
        """构建API请求URL"""
        encoded_query = self.encode_search_query(self.search_query)
        url = (f"https://inner.hunter.qianxin-inc.cn/openApi/search?api-key={self.api_key}"
               f"&search={encoded_query}&page={page}&page_size={self.page_size}"
               f"&is_web={self.is_web}&port_filter=false"
               f"&start_time={self.start_time}&end_time={self.end_time}")
        return url
    
    def load_data(self, page=1, new_search=False):
        """加载数据，使用线程避免界面卡顿"""
        self.message_queue.put(("update_status", "正在加载数据..."))
        
        # 在新线程中执行网络请求
        thread = threading.Thread(target=self._load_data_thread, args=(page, new_search))
        thread.daemon = True
        thread.start()
    
    def _load_data_thread(self, page, new_search):
        """实际的数据加载逻辑，在后台线程中执行"""
        try:
            url = self.build_url(page)
            response = self._request_with_retry(url)
            
            data = response.json()
            
            if data.get("code") == 200:
                result_data = data.get("data", {})
                self.total_results = result_data.get("total", 0)
                self.total_pages = (self.total_results + self.page_size - 1) // self.page_size
                current_data = result_data.get("arr", [])
                
                # 如果是新搜索，清空之前的数据
                if new_search:
                    self.all_data = []
                    self.current_page = 1
                
                # 保存数据
                if page == 1 or new_search:
                    self.all_data = current_data.copy()
                else:
                    self.all_data.extend(current_data)
                
                self.current_page = page
                
                # 更新UI
                self.message_queue.put(("update_table",))
                self.message_queue.put(("update_pagination",))
                self.message_queue.put(("update_status", "数据加载完成"))
            else:
                error_msg = data.get("message", "未知错误")
                self.message_queue.put(("show_error", "API错误", f"API返回错误: {error_msg}"))
                self.message_queue.put(("update_status", "数据加载失败"))
                
        except Exception as e:
            self.message_queue.put(("show_error", "加载错误", f"加载数据时出错: {str(e)}"))
            self.message_queue.put(("update_status", "数据加载失败"))
    
    def _request_with_retry(self, url):
        """带重试机制的请求方法"""
        for attempt in range(self.max_retries):
            try:
                # 每次请求前添加随机延迟，避免请求过于规律
                delay = self.base_delay + random.uniform(0, 1)  # 基础延迟 + 0-1秒随机延迟
                time.sleep(delay)
                
                response = self.session.get(url, timeout=15)
                response.raise_for_status()  # 检查请求是否成功
                
                # 检查是否是请求过多的错误
                if response.status_code == 429:
                    # 指数退避策略，重试间隔逐渐增加
                    retry_after = 2 **attempt + random.uniform(0, 1)
                    time.sleep(retry_after)
                    continue
                    
                return response
                
            except (requests.exceptions.Timeout, 
                    requests.exceptions.ConnectionError, 
                    requests.exceptions.HTTPError) as e:
                
                # 对请求过多的错误进行特殊处理
                if hasattr(e, 'response') and e.response is not None and e.response.status_code == 429:
                    error_msg = f"请求过于频繁，将在{2**(attempt+1)}秒后重试（{attempt+1}/{self.max_retries}）"
                    self.message_queue.put(("update_status", error_msg))
                    # 指数退避
                    time.sleep(2**(attempt+1) + random.uniform(0, 1))
                else:
                    if attempt < self.max_retries - 1:
                        # 其他错误的重试延迟
                        time.sleep(1 + attempt)
                    else:
                        raise Exception(f"请求失败，已重试{self.max_retries}次: {str(e)}")
        
        raise Exception(f"达到最大重试次数（{self.max_retries}次），请求失败")
    
    def update_table(self):
        """更新表格数据"""
        # 清空现有数据
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 获取当前页的数据
        start_idx = (self.current_page - 1) * self.page_size
        end_idx = min(start_idx + self.page_size, len(self.all_data))
        current_page_data = self.all_data[start_idx:end_idx]
        
        # 填充表格，只显示指定的字段
        for item in current_page_data:
            values = []
            for col in self.display_columns:
                # 处理特殊字段
                if col == "is_risk":
                    value = "是" if item.get(col) else "否"
                elif col == "is_risk_protocol":
                    value = "是" if item.get(col) else "否"
                else:
                    value = item.get(col, "")
                values.append(value)
            
            self.tree.insert("", tk.END, values=values)
    
    def update_pagination_info(self):
        """更新分页信息"""
        self.page_info.config(text=f"第 {self.current_page} 页，共 {self.total_pages} 页，总计 {self.total_results} 条数据")
        self.page_entry.delete(0, tk.END)
        self.page_entry.insert(0, str(self.current_page))
        
        # 控制按钮状态
        self.prev_btn.config(state=tk.NORMAL if self.current_page > 1 else tk.DISABLED)
        self.next_btn.config(state=tk.NORMAL if self.current_page < self.total_pages else tk.DISABLED)
    
    def prev_page(self):
        """上一页"""
        if self.current_page > 1:
            self.load_data(self.current_page - 1)
    
    def next_page(self):
        """下一页"""
        if self.current_page < self.total_pages:
            self.load_data(self.current_page + 1)
    
    def go_to_page(self):
        """跳转到指定页"""
        try:
            page = int(self.page_entry.get())
            if 1 <= page <= self.total_pages:
                self.load_data(page)
            else:
                self.message_queue.put(("show_info", "警告", f"页码必须在1到{self.total_pages}之间"))
        except ValueError:
            self.message_queue.put(("show_info", "警告", "请输入有效的页码"))
    
    def on_search(self):
        """执行搜索"""
        self.search_query = self.search_entry.get()
        self.is_web = self.web_type.get()
        try:
            self.page_size = int(self.page_size_var.get())
            self.load_data(1, new_search=True)
        except ValueError:
            self.message_queue.put(("show_info", "警告", "请输入有效的每页数量"))
    
    def export_data(self):
        """导出数据到CSV，优化大文件导出性能"""
        if not self.all_data:
            self.message_queue.put(("show_info", "提示", "没有数据可导出"))
            return
        
        # 询问用户要导出的页数
        try:
            pages = simpledialog.askinteger(
                "导出设置", 
                f"请输入要导出的页数 (1-{self.total_pages}):",
                minvalue=1,
                maxvalue=self.total_pages,
                initialvalue=min(5, self.total_pages)
            )
            
            if pages is None:  # 用户取消
                return
            
            # 显示进度窗口
            progress_window = tk.Toplevel(self.root)
            progress_window.title("导出中")
            progress_window.geometry("400x120")
            progress_window.transient(self.root)  # 设置为主窗口的子窗口
            progress_window.grab_set()  # 模态窗口，阻止操作主窗口
            
            status_label = ttk.Label(progress_window, text="正在准备导出数据...")
            status_label.pack(pady=10)
            
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=pages)
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            
            # 确保进度窗口显示
            progress_window.update_idletasks()
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="保存导出文件"
            )
            
            if not file_path:
                progress_window.destroy()
                return
            
            # 在新线程中执行导出操作
            def export_thread():
                try:
                    # 计算需要加载的页码范围
                    start_page = 1
                    end_page = min(pages, self.total_pages)
                    
                    # 准备CSV文件
                    with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                        # 获取所有可能的字段（包括API返回的所有字段）
                        fieldnames = self.all_possible_fields
                        
                        # 创建DictWriter，设置extrasaction='ignore'来忽略不存在的字段
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                        
                        # 分批加载和写入数据
                        for page in range(start_page, end_page + 1):
                            # 更新进度和状态
                            self.message_queue.put(("update_status", f"正在导出第{page}页数据..."))
                            progress_var.set(page - start_page + 1)
                            progress_window.update_idletasks()
                            
                            # 如果是已加载的数据，直接使用
                            if page <= len(self.all_data) // self.page_size + 1:
                                # 计算当前页在all_data中的索引范围
                                page_start = (page - 1) * self.page_size
                                page_end = min(page_start + self.page_size, len(self.all_data))
                                page_data = self.all_data[page_start:page_end]
                            else:
                                # 需要新加载的数据
                                url = self.build_url(page)
                                response = self._request_with_retry(url)
                                
                                data = response.json()
                                if data.get("code") == 200:
                                    page_data = data.get("data", {}).get("arr", [])
                                else:
                                    raise Exception(f"第{page}页API返回错误: {data.get('message', '未知错误')}")
                            
                            # 写入数据
                            for item in page_data:
                                # 处理特殊字段
                                processed_item = {}
                                for key, value in item.items():
                                    if key == "is_risk" or key == "is_risk_protocol":
                                        processed_item[key] = "是" if value else "否"
                                    else:
                                        processed_item[key] = value
                                writer.writerow(processed_item)
                    
                    # 导出完成
                    self.message_queue.put(("show_info", "成功", f"数据已成功导出到:\n{file_path}"))
                    self.message_queue.put(("update_status", "导出完成"))
                    
                except Exception as e:
                    self.message_queue.put(("show_error", "导出错误", f"导出失败: {str(e)}"))
                    self.message_queue.put(("update_status", "导出失败"))
                finally:
                    progress_window.destroy()
            
            # 启动导出线程
            thread = threading.Thread(target=export_thread)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            self.message_queue.put(("show_error", "错误", f"导出数据时出错: {str(e)}"))

if __name__ == "__main__":
    root = tk.Tk()
    app = HunterVisualizer(root)
    root.mainloop()
