import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import string
import random
from collections import Counter
import re
import json
import os

class MonoalphabeticCipher:
    def __init__(self, key=None):
        """初始化单表代换密码工具"""
        self.alphabet = string.ascii_lowercase
        if key is None:
            self.key = self.generate_random_key()
        else:
            self.key = key.lower()
            if len(self.key) != 26 or not set(self.key) == set(self.alphabet):
                self.key = self.generate_random_key()
        self.reverse_key = self.create_reverse_key()
        
    def generate_random_key(self):
        """生成随机密钥"""
        letters = list(self.alphabet)
        random.shuffle(letters)
        return ''.join(letters)
    
    def create_reverse_key(self):
        """创建反向密钥用于解密"""
        return {v: k for k, v in zip(self.alphabet, self.key)}
    
    def encrypt(self, plaintext):
        """加密文本"""
        plaintext = plaintext.lower()
        ciphertext = []
        for char in plaintext:
            if char in self.alphabet:
                ciphertext.append(self.key[self.alphabet.index(char)])
            else:
                ciphertext.append(char)
        return ''.join(ciphertext)
    
    def decrypt(self, ciphertext):
        """解密文本"""
        ciphertext = ciphertext.lower()
        plaintext = []
        for char in ciphertext:
            if char in self.alphabet:
                plaintext.append(self.alphabet[self.key.index(char)])
            else:
                plaintext.append(char)
        return ''.join(plaintext)
    
    @staticmethod
    def letter_frequency(text):
        """计算字母频率"""
        text = re.sub(r'[^a-z]', '', text.lower())
        count = Counter(text)
        total = sum(count.values())
        return {char: count[char] / total * 100 for char in string.ascii_lowercase}
    
    @staticmethod
    def bigram_frequency(text):
        """计算双字母组合频率"""
        text = re.sub(r'[^a-z]', '', text.lower())
        bigrams = [text[i:i+2] for i in range(len(text)-1)]
        count = Counter(bigrams)
        total = sum(count.values())
        return {bg: count[bg] / total * 100 for bg in count if count[bg] > 0}
    
    @staticmethod
    def get_english_frequency():
        """返回标准英文字母频率"""
        return {
            'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 
            'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 
            'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.30, 
            'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 
            'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
        }
    
    @staticmethod
    def get_common_bigrams():
        """返回常见英文双字母组合"""
        return [
            'th', 'he', 'in', 'er', 'an', 're', 'ed', 'on', 'es', 'st', 
            'en', 'at', 'to', 'nt', 'ha', 'nd', 'ou', 'ea', 'ng', 'as'
        ]
    
    @staticmethod
    def get_common_words():
        """返回常见英文单词"""
        return [
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at'
        ]


class CipherToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("单表代换辅助工具")
        self.root.geometry("1100x850")
        self.root.configure(bg="#f0f0f0")
        
        # 创建样式
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", padding=6, font=("Arial", 10))
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("TNotebook", background="#f0f0f0")
        self.style.configure("TNotebook.Tab", font=("Arial", 10, "bold"), padding=[10, 5])
        
        # 创建选项卡
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 创建加密选项卡
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="加密")
        self.create_encrypt_tab()
        
        # 创建解密选项卡
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="解密")
        self.create_decrypt_tab()
        
        # 创建破译辅助选项卡
        self.crack_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.crack_frame, text="破译辅助")
        self.create_crack_tab()
        
        # 初始化密码工具
        self.cipher = MonoalphabeticCipher()
        self.update_key_displays()
        
        # 初始化破译状态
        self.ciphertext_to_crack = ""
        self.current_key_guess = {char: None for char in string.ascii_lowercase}
        self.user_mappings = {}
        self.key_history = []
        self.possible_mappings = {}
    
    def create_encrypt_tab(self):
        """创建加密选项卡"""
        # 密钥部分
        key_frame = ttk.LabelFrame(self.encrypt_frame, text="密钥设置")
        key_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(key_frame, text="当前密钥:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_display_encrypt = ttk.Label(key_frame, text="", font=("Courier", 12), background="white", width=60)
        self.key_display_encrypt.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(key_btn_frame, text="生成随机密钥", command=self.generate_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="输入自定义密钥", command=self.custom_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="保存密钥", command=self.save_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="加载密钥", command=self.load_key).pack(side="left", padx=5)
        
        # 输入输出部分
        io_frame = ttk.LabelFrame(self.encrypt_frame, text="加密操作")
        io_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(io_frame, text="明文输入:").pack(anchor="w", padx=5, pady=2)
        self.plaintext_input = scrolledtext.ScrolledText(io_frame, width=90, height=10, font=("Arial", 10))
        self.plaintext_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(io_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="加密", command=self.encrypt_text).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="清空", command=lambda: self.clear_text(self.plaintext_input, self.ciphertext_output)).pack(side="left", padx=5)
        
        ttk.Label(io_frame, text="密文输出:").pack(anchor="w", padx=5, pady=2)
        self.ciphertext_output = scrolledtext.ScrolledText(io_frame, width=90, height=10, font=("Arial", 10))
        self.ciphertext_output.pack(fill="both", expand=True, padx=5, pady=5)
        self.ciphertext_output.config(state="disabled")
    
    def create_decrypt_tab(self):
        """创建解密选项卡"""
        # 密钥部分
        key_frame = ttk.LabelFrame(self.decrypt_frame, text="密钥设置")
        key_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(key_frame, text="当前密钥:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.key_display_decrypt = ttk.Label(key_frame, text="", font=("Courier", 12), background="white", width=60)
        self.key_display_decrypt.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        key_btn_frame = ttk.Frame(key_frame)
        key_btn_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(key_btn_frame, text="生成随机密钥", command=self.generate_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="输入自定义密钥", command=self.custom_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="保存密钥", command=self.save_key).pack(side="left", padx=5)
        ttk.Button(key_btn_frame, text="加载密钥", command=self.load_key).pack(side="left", padx=5)
        
        # 输入输出部分
        io_frame = ttk.LabelFrame(self.decrypt_frame, text="解密操作")
        io_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(io_frame, text="密文输入:").pack(anchor="w", padx=5, pady=2)
        self.ciphertext_input = scrolledtext.ScrolledText(io_frame, width=90, height=10, font=("Arial", 10))
        self.ciphertext_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(io_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="解密", command=self.decrypt_text).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="清空", command=lambda: self.clear_text(self.ciphertext_input, self.plaintext_output)).pack(side="left", padx=5)
        
        ttk.Label(io_frame, text="明文输出:").pack(anchor="w", padx=5, pady=2)
        self.plaintext_output = scrolledtext.ScrolledText(io_frame, width=90, height=10, font=("Arial", 10))
        self.plaintext_output.pack(fill="both", expand=True, padx=5, pady=5)
        self.plaintext_output.config(state="disabled")
    
    def create_crack_tab(self):
        """创建破译辅助选项卡"""
        main_frame = ttk.Frame(self.crack_frame)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 左侧面板：密文输入和分析
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # 密文输入部分
        input_frame = ttk.LabelFrame(left_frame, text="密文输入")
        input_frame.pack(fill="x", padx=5, pady=5)
        
        self.ciphertext_entry = scrolledtext.ScrolledText(input_frame, width=60, height=6, font=("Arial", 10))
        self.ciphertext_entry.pack(fill="both", expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="分析密文", command=self.analyze_ciphertext).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="清空密文", command=self.clear_ciphertext).pack(side="left", padx=5)
        
        # 分析结果显示部分
        analysis_frame = ttk.LabelFrame(left_frame, text="分析结果与建议")
        analysis_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 使用Notebook显示不同类型的分析
        analysis_notebook = ttk.Notebook(analysis_frame)
        analysis_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 字母频率分析
        freq_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(freq_frame, text="字母频率")
        
        ttk.Label(freq_frame, text="密文字母频率:").pack(anchor="w", padx=5, pady=2)
        self.cipher_freq_text = scrolledtext.ScrolledText(freq_frame, width=60, height=8, font=("Courier", 10))
        self.cipher_freq_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.cipher_freq_text.config(state="disabled")
        
        # 双字母频率分析
        bigram_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(bigram_frame, text="双字母频率")
        
        ttk.Label(bigram_frame, text="密文双字母组合频率:").pack(anchor="w", padx=5, pady=2)
        self.bigram_freq_text = scrolledtext.ScrolledText(bigram_frame, width=60, height=8, font=("Courier", 10))
        self.bigram_freq_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.bigram_freq_text.config(state="disabled")
        
        # 右侧面板：映射设置和结果
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # 用户映射部分
        mapping_frame = ttk.LabelFrame(right_frame, text="映射设置")
        mapping_frame.pack(fill="x", padx=5, pady=5)
        
        mapping_control_frame = ttk.Frame(mapping_frame)
        mapping_control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(mapping_control_frame, text="密文字母:").grid(row=0, column=0, padx=5, pady=5)
        self.cipher_char = ttk.Combobox(mapping_control_frame, values=list(string.ascii_lowercase), width=3)
        self.cipher_char.grid(row=0, column=1, padx=5, pady=5)
        self.cipher_char.current(0)
        
        ttk.Label(mapping_control_frame, text="映射为:").grid(row=0, column=2, padx=5, pady=5)
        self.plain_char = ttk.Combobox(mapping_control_frame, values=list(string.ascii_lowercase), width=3)
        self.plain_char.grid(row=0, column=3, padx=5, pady=5)
        self.plain_char.current(4)  # 默认选择E，英文中最常见的字母
        
        ttk.Button(mapping_control_frame, text="添加映射", command=self.add_mapping).grid(row=0, column=4, padx=10, pady=5)
        ttk.Button(mapping_control_frame, text="移除映射", command=self.remove_mapping).grid(row=0, column=5, padx=5, pady=5)
        ttk.Button(mapping_control_frame, text="清空映射", command=self.clear_mappings).grid(row=0, column=6, padx=5, pady=5)
        
        # 当前映射显示
        ttk.Label(mapping_frame, text="当前映射:").pack(anchor="w", padx=5, pady=2)
        self.mapping_display = scrolledtext.ScrolledText(mapping_frame, height=5, font=("Courier", 10))
        self.mapping_display.pack(fill="x", padx=5, pady=5)
        self.mapping_display.insert("1.0", "无映射")
        self.mapping_display.config(state="disabled")
        
        # 破译结果显示
        result_frame = ttk.LabelFrame(right_frame, text="破译结果")
        result_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        ttk.Label(result_frame, text="部分解密文本:").pack(anchor="w", padx=5, pady=2)
        self.partial_decrypt_text = scrolledtext.ScrolledText(result_frame, height=15, font=("Arial", 10))
        self.partial_decrypt_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.partial_decrypt_text.config(state="normal")
        
        # 底部按钮 - 确保它们可见
        button_frame = ttk.Frame(self.crack_frame)
        button_frame.pack(fill="x", padx=10, pady=10, side=tk.BOTTOM)
        
        ttk.Button(button_frame, text="应用映射并更新", command=self.apply_mappings).pack(side="left", padx=5)
        ttk.Button(button_frame, text="智能建议", command=self.smart_suggestions).pack(side="left", padx=5)
        ttk.Button(button_frame, text="重置所有分析", command=self.reset_analysis).pack(side="left", padx=5)
        ttk.Button(button_frame, text="导出完整密钥", command=self.export_key).pack(side="right", padx=5)
        ttk.Button(button_frame, text="保存当前状态", command=self.save_crack_state).pack(side="right", padx=5)
        ttk.Button(button_frame, text="加载历史状态", command=self.load_crack_state).pack(side="right", padx=5)
    
    def clear_ciphertext(self):
        """清空密文输入"""
        self.ciphertext_entry.delete("1.0", "end")
    
    def generate_key(self):
        """生成随机密钥"""
        self.cipher = MonoalphabeticCipher()
        self.update_key_displays()
        messagebox.showinfo("密钥生成", "已生成新的随机密钥")
    
    def custom_key(self):
        """输入自定义密钥"""
        dialog = tk.Toplevel(self.root)
        dialog.title("输入自定义密钥")
        dialog.geometry("500x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="请输入26个字母的密钥（不重复且包含所有字母）:").pack(padx=10, pady=10)
        
        key_var = tk.StringVar()
        key_entry = ttk.Entry(dialog, textvariable=key_var, width=30, font=("Courier", 12))
        key_entry.pack(padx=10, pady=5)
        key_entry.focus_set()
        
        def set_key():
            key = key_var.get().lower()
            if len(key) != 26 or not set(key) == set(string.ascii_lowercase):
                messagebox.showerror("错误", "密钥必须包含26个不重复的字母")
                return
            self.cipher = MonoalphabeticCipher(key)
            self.update_key_displays()
            dialog.destroy()
            messagebox.showinfo("密钥设置", "自定义密钥设置成功")
        
        ttk.Button(dialog, text="确定", command=set_key).pack(pady=10)
        dialog.bind("<Return>", lambda e: set_key())
    
    def save_key(self):
        """保存密钥到文件"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="保存密钥"
        )
        if not file_path:
            return
        
        key_data = {
            "key": self.cipher.key,
            "reverse_key": self.cipher.reverse_key
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(key_data, f)
            messagebox.showinfo("保存成功", f"密钥已保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("保存失败", f"保存密钥时出错: {str(e)}")
    
    def load_key(self):
        """从文件加载密钥"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="加载密钥"
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                key_data = json.load(f)
            
            if "key" not in key_data or len(key_data["key"]) != 26:
                messagebox.showerror("加载失败", "密钥文件格式无效")
                return
            
            self.cipher = MonoalphabeticCipher(key_data["key"])
            self.update_key_displays()
            messagebox.showinfo("加载成功", "密钥已成功加载")
        except Exception as e:
            messagebox.showerror("加载失败", f"加载密钥时出错: {str(e)}")
    
    def update_key_displays(self):
        """更新所有选项卡中的密钥显示"""
        key = self.cipher.key
        display = " ".join(key[i:i+5] for i in range(0, 26, 5))
        if hasattr(self, 'key_display_encrypt'):
            self.key_display_encrypt.config(text=display)
        if hasattr(self, 'key_display_decrypt'):
            self.key_display_decrypt.config(text=display)
    
    def encrypt_text(self):
        """加密文本"""
        plaintext = self.plaintext_input.get("1.0", "end-1c")
        if not plaintext:
            messagebox.showwarning("警告", "请输入要加密的文本")
            return
        
        ciphertext = self.cipher.encrypt(plaintext)
        self.ciphertext_output.config(state="normal")
        self.ciphertext_output.delete("1.0", "end")
        self.ciphertext_output.insert("1.0", ciphertext)
        self.ciphertext_output.config(state="disabled")
    
    def decrypt_text(self):
        """解密文本"""
        ciphertext = self.ciphertext_input.get("1.0", "end-1c")
        if not ciphertext:
            messagebox.showwarning("警告", "请输入要解密的文本")
            return
        
        plaintext = self.cipher.decrypt(ciphertext)
        self.plaintext_output.config(state="normal")
        self.plaintext_output.delete("1.0", "end")
        self.plaintext_output.insert("1.0", plaintext)
        self.plaintext_output.config(state="disabled")
    
    def clear_text(self, input_widget, output_widget):
        """清空输入输出"""
        input_widget.delete("1.0", "end")
        output_widget.config(state="normal")
        output_widget.delete("1.0", "end")
        output_widget.config(state="disabled")
    
    def analyze_ciphertext(self):
        """分析密文"""
        self.ciphertext_to_crack = self.ciphertext_entry.get("1.0", "end-1c").lower()
        if not self.ciphertext_to_crack:
            messagebox.showwarning("警告", "请输入要分析的密文")
            return
        
        # 保存当前状态到历史
        self.save_current_state_to_history()
        
        # 分析字母频率
        freq = MonoalphabeticCipher.letter_frequency(self.ciphertext_to_crack)
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        
        self.cipher_freq_text.config(state="normal")
        self.cipher_freq_text.delete("1.0", "end")
        
        # 显示密文字母频率
        self.cipher_freq_text.insert("end", "密文字母频率 (降序排列):\n")
        self.cipher_freq_text.insert("end", "-" * 50 + "\n")
        for char, freq_val in sorted_freq:
            self.cipher_freq_text.insert("end", f"{char}: {freq_val:.2f}%\n")
        
        # 显示标准英文字母频率参考
        standard_freq = MonoalphabeticCipher.get_english_frequency()
        sorted_standard = sorted(standard_freq.items(), key=lambda x: x[1], reverse=True)
        
        self.cipher_freq_text.insert("end", "\n标准英文字母频率 (降序排列):\n")
        self.cipher_freq_text.insert("end", "-" * 50 + "\n")
        for char, freq_val in sorted_standard:
            self.cipher_freq_text.insert("end", f"{char}: {freq_val:.2f}%\n")
        
        self.cipher_freq_text.insert("end", "\n建议: 尝试将高频密文字母映射到高频明文字母")
        self.cipher_freq_text.config(state="disabled")
        
        # 分析双字母频率
        bigrams = MonoalphabeticCipher.bigram_frequency(self.ciphertext_to_crack)
        sorted_bigrams = sorted(bigrams.items(), key=lambda x: x[1], reverse=True)[:20]
        
        self.bigram_freq_text.config(state="normal")
        self.bigram_freq_text.delete("1.0", "end")
        
        # 显示密文双字母频率
        self.bigram_freq_text.insert("end", "密文常见双字母组合 (前20个):\n")
        self.bigram_freq_text.insert("end", "-" * 50 + "\n")
        for bg, freq_val in sorted_bigrams:
            self.bigram_freq_text.insert("end", f"{bg}: {freq_val:.2f}%\n")
        
        # 显示标准英文双字母频率参考
        standard_bigrams = MonoalphabeticCipher.get_common_bigrams()
        
        self.bigram_freq_text.insert("end", "\n标准英文常见双字母组合:\n")
        self.bigram_freq_text.insert("end", "-" * 50 + "\n")
        self.bigram_freq_text.insert("end", ", ".join(standard_bigrams))
        
        self.bigram_freq_text.insert("end", "\n\n建议: 尝试将常见双字母组合映射到英文常见组合")
        self.bigram_freq_text.config(state="disabled")
        
        # 重置当前密钥猜测和用户映射
        self.current_key_guess = {char: None for char in string.ascii_lowercase}
        self.user_mappings = {}
        self.update_mapping_display()
        self.partial_decrypt_text.config(state="normal")
        self.partial_decrypt_text.delete("1.0", "end")
        self.partial_decrypt_text.insert("1.0", "请添加映射并点击'应用映射并更新'")
        self.partial_decrypt_text.config(state="disabled")
        
        # 生成初始可能映射
        self.generate_possible_mappings()
    
    def generate_possible_mappings(self):
        """生成可能的字母映射建议"""
        # 基于频率分析生成可能的映射
        cipher_freq = MonoalphabeticCipher.letter_frequency(self.ciphertext_to_crack)
        sorted_cipher = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
        english_freq = sorted(MonoalphabeticCipher.get_english_frequency().items(), key=lambda x: x[1], reverse=True)
        
        self.possible_mappings = {}
        for i in range(min(len(sorted_cipher), len(english_freq))):
            cipher_char, _ = sorted_cipher[i]
            plain_char, _ = english_freq[i]
            self.possible_mappings[cipher_char] = plain_char
        
        # 基于常见双字母组合调整
        cipher_bigrams = MonoalphabeticCipher.bigram_frequency(self.ciphertext_to_crack)
        sorted_cipher_bigrams = sorted(cipher_bigrams.items(), key=lambda x: x[1], reverse=True)[:10]
        common_bigrams = MonoalphabeticCipher.get_common_bigrams()[:10]
        
        for i in range(min(len(sorted_cipher_bigrams), len(common_bigrams))):
            cipher_bg, _ = sorted_cipher_bigrams[i]
            common_bg = common_bigrams[i]
            
            # 更新第一个字母的映射
            if cipher_bg[0] in self.possible_mappings:
                self.possible_mappings[cipher_bg[0]] = common_bg[0]
            
            # 更新第二个字母的映射
            if cipher_bg[1] in self.possible_mappings:
                self.possible_mappings[cipher_bg[1]] = common_bg[1]
    
    def add_mapping(self):
        """添加映射关系"""
        cipher_char = self.cipher_char.get().lower()
        plain_char = self.plain_char.get().lower()
        
        if not cipher_char or not plain_char:
            messagebox.showwarning("警告", "请选择密文字母和明文字母")
            return
        
        # 检查映射是否冲突
        for c, p in self.user_mappings.items():
            if p == plain_char and c != cipher_char:
                messagebox.showwarning("冲突", f"明文字母 '{plain_char}' 已经映射到 '{c}'")
                return
            if c == cipher_char and p != plain_char:
                messagebox.showwarning("冲突", f"密文字母 '{cipher_char}' 已经映射到 '{p}'")
                return
        
        self.user_mappings[cipher_char] = plain_char
        self.update_mapping_display()
    
    def remove_mapping(self):
        """移除映射关系"""
        cipher_char = self.cipher_char.get().lower()
        if cipher_char in self.user_mappings:
            del self.user_mappings[cipher_char]
            self.update_mapping_display()
    
    def clear_mappings(self):
        """清空所有映射"""
        self.user_mappings = {}
        self.update_mapping_display()
    
    def update_mapping_display(self):
        """更新映射显示"""
        self.mapping_display.config(state="normal")
        self.mapping_display.delete("1.0", "end")
        
        if not self.user_mappings:
            self.mapping_display.insert("end", "无映射")
        else:
            for cipher_char, plain_char in self.user_mappings.items():
                self.mapping_display.insert("end", f"{cipher_char} → {plain_char}\n")
        
        self.mapping_display.config(state="disabled")
    
    def apply_mappings(self):
        """应用映射并更新部分解密文本"""
        if not self.ciphertext_to_crack:
            messagebox.showwarning("警告", "请先输入密文并进行分析")
            return
        
        # 保存当前状态到历史
        self.save_current_state_to_history()
        
        # 更新当前密钥猜测
        for cipher_char, plain_char in self.user_mappings.items():
            self.current_key_guess[cipher_char] = plain_char
        
        # 创建部分解密文本
        partial_text = []
        for char in self.ciphertext_to_crack:
            if char in self.current_key_guess and self.current_key_guess[char]:
                partial_text.append(self.current_key_guess[char])
            else:
                # 显示为红色大写字母，表示未解密
                partial_text.append(char.upper())
        
        partial_text = ''.join(partial_text)
        
        self.partial_decrypt_text.config(state="normal")
        self.partial_decrypt_text.delete("1.0", "end")
        
        # 配置标签用于高亮显示
        self.partial_decrypt_text.tag_configure("decrypted", foreground="black")
        self.partial_decrypt_text.tag_configure("undecrypted", foreground="red", font=("Arial", 10, "bold"))
        
        # 插入文本并应用标签
        self.partial_decrypt_text.insert("1.0", partial_text)
        
        # 为未解密的字符添加高亮
        for i, char in enumerate(partial_text):
            if char.isupper():
                self.partial_decrypt_text.tag_add("undecrypted", f"1.{i}", f"1.{i+1}")
            else:
                self.partial_decrypt_text.tag_add("decrypted", f"1.{i}", f"1.{i+1}")
        
        self.partial_decrypt_text.config(state="disabled")
        
        # 提供进一步建议
        self.provide_suggestions()
    
    def smart_suggestions(self):
        """提供智能建议"""
        if not self.ciphertext_to_crack:
            messagebox.showwarning("警告", "请先输入密文并进行分析")
            return
        
        # 获取部分解密文本
        partial_text = self.partial_decrypt_text.get("1.0", "end-1c")
        
        # 查找可能的不完整单词
        words = re.findall(r'\b\w+\b', partial_text)
        incomplete_words = [word for word in words if any(char.isupper() for char in word) and len(word) > 2]
        
        suggestions = []
        
        if incomplete_words:
            suggestions.append("发现以下可能的不完整单词:")
            for word in incomplete_words[:5]:  # 最多显示5个
                suggestions.append(f"- {word}")
            suggestions.append("")
        
        # 检查常见单词
        common_words = MonoalphabeticCipher.get_common_words()
        found_words = [word for word in common_words if word in partial_text.lower()]
        
        if found_words:
            suggestions.append("检测到以下常见单词:")
            suggestions.append(", ".join(found_words))
            suggestions.append("")
        
        # 基于频率分析的建议
        undecrypted_chars = set(char for char in self.ciphertext_to_crack if char.isalpha() and self.current_key_guess.get(char) is None)
        
        if undecrypted_chars:
            suggestions.append("以下字母尚未映射:")
            suggestions.append(", ".join(sorted(undecrypted_chars)))
            suggestions.append("")
            
            # 提供可能的映射建议
            cipher_freq = MonoalphabeticCipher.letter_frequency(self.ciphertext_to_crack)
            sorted_undecrypted = sorted([(c, cipher_freq.get(c, 0)) for c in undecrypted_chars], key=lambda x: x[1], reverse=True)
            
            english_freq = sorted(MonoalphabeticCipher.get_english_frequency().items(), key=lambda x: x[1], reverse=True)
            available_plain_chars = [p for p, _ in english_freq if p not in self.user_mappings.values()]
            
            if sorted_undecrypted and available_plain_chars:
                suggestions.append("映射建议 (基于频率):")
                for i in range(min(3, len(sorted_undecrypted), len(available_plain_chars))):
                    cipher_char, freq = sorted_undecrypted[i]
                    plain_char = available_plain_chars[i]
                    suggestions.append(f"  {cipher_char} → {plain_char}")
                suggestions.append("")
        
        # 如果没有建议，添加一般性建议
        if not suggestions:
            suggestions = [
                "1. 查看部分解密文本中红色大写字母（未解密部分）周围的上下文",
                "2. 尝试识别常见单词模式（如'the', 'and', 'ing'等）",
                "3. 注意重复出现的字母组合",
                "4. 考虑英文中常见的字母连接（如'q'后通常跟'u'）",
                "5. 尝试将未解密的字母映射到剩余的明文字母"
            ]
        
        # 显示建议
        self.bigram_freq_text.config(state="normal")
        self.bigram_freq_text.delete("1.0", "end")
        self.bigram_freq_text.insert("end", "智能建议:\n")
        self.bigram_freq_text.insert("end", "-" * 50 + "\n")
        
        for suggestion in suggestions:
            self.bigram_freq_text.insert("end", suggestion + "\n")
        
        self.bigram_freq_text.config(state="disabled")
    
    def provide_suggestions(self):
        """根据上下文提供进一步建议"""
        # 获取部分解密文本
        partial_text = self.partial_decrypt_text.get("1.0", "end-1c")
        
        # 查找可能的不完整单词
        words = re.findall(r'\b\w+\b', partial_text)
        incomplete_words = [word for word in words if any(char.isupper() for char in word) and len(word) > 2]
        
        suggestions = []
        
        if incomplete_words:
            suggestions.append("发现以下可能的不完整单词:")
            for word in incomplete_words[:5]:  # 最多显示5个
                suggestions.append(f"- {word}")
            suggestions.append("")
        
        # 检查常见单词
        common_words = MonoalphabeticCipher.get_common_words()
        found_words = [word for word in common_words if word in partial_text.lower()]
        
        if found_words:
            suggestions.append("检测到以下常见单词:")
            suggestions.append(", ".join(found_words))
            suggestions.append("")
        
        # 添加一般性建议
        suggestions.extend([
            "1. 查看部分解密文本中红色大写字母（未解密部分）周围的上下文",
            "2. 尝试识别常见单词模式（如'the', 'and', 'ing'等）",
            "3. 注意重复出现的字母组合",
            "4. 考虑英文中常见的字母连接（如'q'后通常跟'u'）",
            "5. 尝试将未解密的字母映射到剩余的明文字母"
        ])
        
        # 显示建议
        self.bigram_freq_text.config(state="normal")
        self.bigram_freq_text.delete("1.0", "end")
        self.bigram_freq_text.insert("end", "建议:\n")
        self.bigram_freq_text.insert("end", "-" * 50 + "\n")
        
        for suggestion in suggestions:
            self.bigram_freq_text.insert("end", suggestion + "\n")
        
        self.bigram_freq_text.config(state="disabled")
    
    def save_current_state_to_history(self):
        """保存当前破译状态到历史"""
        state = {
            "ciphertext": self.ciphertext_to_crack,
            "mappings": self.user_mappings.copy(),
            "key_guess": self.current_key_guess.copy(),
            "partial_text": self.partial_decrypt_text.get("1.0", "end-1c") if self.partial_decrypt_text else ""
        }
        self.key_history.append(state)
    
    def save_crack_state(self):
        """保存破译状态到文件"""
        if not self.key_history:
            messagebox.showwarning("警告", "没有可保存的破译状态")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="保存破译状态"
        )
        if not file_path:
            return
        
        current_state = {
            "ciphertext": self.ciphertext_to_crack,
            "mappings": self.user_mappings,
            "key_guess": self.current_key_guess,
            "history": self.key_history
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(current_state, f)
            messagebox.showinfo("保存成功", f"破译状态已保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("保存失败", f"保存破译状态时出错: {str(e)}")
    
    def load_crack_state(self):
        """从文件加载破译状态"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="加载破译状态"
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                state = json.load(f)
            
            self.ciphertext_to_crack = state.get("ciphertext", "")
            self.user_mappings = state.get("mappings", {})
            self.current_key_guess = state.get("key_guess", {char: None for char in string.ascii_lowercase})
            self.key_history = state.get("history", [])
            
            # 更新界面
            self.ciphertext_entry.delete("1.0", "end")
            self.ciphertext_entry.insert("1.0", self.ciphertext_to_crack)
            self.update_mapping_display()
            
            self.partial_decrypt_text.config(state="normal")
            self.partial_decrypt_text.delete("1.0", "end")
            partial_text = state.get("partial_text", "")
            self.partial_decrypt_text.insert("1.0", partial_text)
            self.partial_decrypt_text.config(state="disabled")
            
            messagebox.showinfo("加载成功", "破译状态已成功加载")
        except Exception as e:
            messagebox.showerror("加载失败", f"加载破译状态时出错: {str(e)}")
    
    def reset_analysis(self):
        """重置所有分析"""
        self.ciphertext_entry.delete("1.0", "end")
        self.cipher_freq_text.config(state="normal")
        self.cipher_freq_text.delete("1.0", "end")
        self.cipher_freq_text.config(state="disabled")
        self.bigram_freq_text.config(state="normal")
        self.bigram_freq_text.delete("1.0", "end")
        self.bigram_freq_text.config(state="disabled")
        self.partial_decrypt_text.config(state="normal")
        self.partial_decrypt_text.delete("1.0", "end")
        self.partial_decrypt_text.config(state="disabled")
        self.mapping_display.config(state="normal")
        self.mapping_display.delete("1.0", "end")
        self.mapping_display.insert("1.0", "无映射")
        self.mapping_display.config(state="disabled")
        self.user_mappings = {}
        self.current_key_guess = {char: None for char in string.ascii_lowercase}
        self.ciphertext_to_crack = ""
        self.key_history = []
        self.possible_mappings = {}
    
    def export_key(self):
        """导出完整密钥"""
        # 检查是否所有字母都已映射
        missing = [char for char in string.ascii_lowercase if self.current_key_guess.get(char) is None]
        if missing:
            messagebox.showwarning("警告", f"以下字母尚未映射: {', '.join(missing)}")
            return
        
        # 构建完整密钥
        key = ''.join(self.current_key_guess[char] for char in string.ascii_lowercase)
        
        # 创建密钥显示对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("导出完整密钥")
        dialog.geometry("600x300")
        
        ttk.Label(dialog, text="完整密钥:", font=("Arial", 12, "bold")).pack(pady=10)
        
        key_text = scrolledtext.ScrolledText(dialog, width=70, height=4, font=("Courier", 12))
        key_text.pack(padx=10, pady=5)
        key_text.insert("1.0", key)
        key_text.config(state="disabled")
        
        ttk.Label(dialog, text="密钥映射关系:", font=("Arial", 12, "bold")).pack(pady=10)
        
        mapping_text = "\n".join(f"{c} → {p}" for c, p in self.current_key_guess.items())
        mapping_display = scrolledtext.ScrolledText(dialog, width=70, height=8, font=("Courier", 10))
        mapping_display.pack(padx=10, pady=5)
        mapping_display.insert("1.0", mapping_text)
        mapping_display.config(state="disabled")
        
        ttk.Button(dialog, text="关闭", command=dialog.destroy).pack(pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = CipherToolGUI(root)
    root.mainloop()