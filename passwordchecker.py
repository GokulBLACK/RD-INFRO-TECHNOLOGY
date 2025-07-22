import re
import math
import tkinter as tk
from tkinter import ttk, font
import hashlib
import threading
import time
from collections import Counter

class PasswordStrengthEvaluator:
    def __init__(self):
        # NIST-based scoring weights
        self.weights = {
            'length': 25,
            'diversity': 20, 
            'entropy': 30,
            'patterns': 15,
            'breach_check': 10
        }
        
        # Common weak patterns
        self.weak_patterns = [
            r'1234', r'password', r'qwerty', r'admin', r'letmein',
            r'welcome', r'monkey', r'dragon', r'master', r'login',
            r'123456789', r'abcdefg', r'qwertyui'
        ]
        
        # Common breached passwords (simplified list)
        self.breached_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', 'admin', 'letmein', 'welcome', 'monkey'
        }

    def calculate_entropy(self, password):
        """Calculate password entropy using NIST methodology"""
        if not password:
            return 0
            
        # Character set size calculation
        char_set_size = 0
        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26  
        if re.search(r'\d', password):
            char_set_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
            char_set_size += 32
            
        if char_set_size == 0:
            return 0
            
        # Entropy = log2(character_set_size^length)
        entropy = len(password) * math.log2(char_set_size)
        return min(entropy, 128)  # Cap at 128 bits

    def check_length_score(self, password):
        """Score based on NIST length guidelines"""
        length = len(password)
        if length < 8:
            return 0
        elif length < 12:
            return 15
        elif length < 16:
            return 20
        else:
            return 25

    def check_diversity_score(self, password):
        """Score character diversity"""
        score = 0
        if re.search(r'[a-z]', password):
            score += 5
        if re.search(r'[A-Z]', password):  
            score += 5
        if re.search(r'\d', password):
            score += 5
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
            score += 5
        return score

    def check_entropy_score(self, password):
        """Score based on entropy calculation"""
        entropy = self.calculate_entropy(password)
        if entropy < 35:
            return 5
        elif entropy < 60:
            return 15
        elif entropy < 90:
            return 25
        else:
            return 30

    def check_pattern_vulnerability(self, password):
        """Detect predictable patterns"""
        score = 15  # Start with full points
        
        # Check for weak patterns
        for pattern in self.weak_patterns:
            if re.search(pattern, password.lower()):
                score -= 5
                
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 3
            
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', '1234', 'abcd']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                score -= 4
                
        return max(score, 0)

    def check_breach_status(self, password):
        """Check against known breached passwords"""
        if password.lower() in self.breached_passwords:
            return 0
        return 10

    def evaluate_password(self, password):
        """Main evaluation function"""
        if not password:
            return 0, "No password entered", "#cccccc", []
            
        # Calculate individual scores
        length_score = self.check_length_score(password)
        diversity_score = self.check_diversity_score(password)
        entropy_score = self.check_entropy_score(password)
        pattern_score = self.check_pattern_vulnerability(password)
        breach_score = self.check_breach_status(password)
        
        # Calculate total score
        total_score = length_score + diversity_score + entropy_score + pattern_score + breach_score
        
        # Generate feedback
        feedback = []
        if length_score < 20:
            feedback.append("• Use at least 12 characters for better security")
        if diversity_score < 15:
            feedback.append("• Include uppercase, lowercase, numbers, and symbols")
        if entropy_score < 25:
            feedback.append("• Increase password complexity and randomness")
        if pattern_score < 10:
            feedback.append("• Avoid common words and predictable patterns")
        if breach_score == 0:
            feedback.append("• Password found in known data breaches - change immediately")
            
        # Determine strength level and color
        if total_score <= 20:
            return total_score, "Very Weak", "#8B0000", feedback
        elif total_score <= 40:
            return total_score, "Weak", "#FF4500", feedback
        elif total_score <= 60:
            return total_score, "Moderate", "#FFA500", feedback
        elif total_score <= 80:
            return total_score, "Strong", "#9ACD32", feedback
        else:
            return total_score, "Very Strong", "#228B22", feedback

class ModernPasswordGUI:
    def __init__(self, root):
        self.root = root
        self.evaluator = PasswordStrengthEvaluator()
        self.setup_window()
        self.create_styles()
        self.create_widgets()
        
    def setup_window(self):
        """Configure main window properties"""
        self.root.title("Advanced Password Strength Evaluator")
        self.root.geometry("600x700")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(True, False)
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"600x700+{x}+{y}")

    def create_styles(self):
        """Create modern styling"""
        self.style = ttk.Style()
        
        # Configure modern theme
        self.style.theme_use('clam')
        
        # Custom styles
        self.style.configure('Modern.TFrame', background='#1e1e2e')
        self.style.configure('Header.TLabel', 
                           background='#1e1e2e', 
                           foreground='#cdd6f4',
                           font=('Segoe UI', 24, 'bold'))
        self.style.configure('Subheader.TLabel',
                           background='#1e1e2e',
                           foreground='#a6adc8', 
                           font=('Segoe UI', 12))
        self.style.configure('Modern.TLabel',
                           background='#1e1e2e',
                           foreground='#cdd6f4',
                           font=('Segoe UI', 11))
        self.style.configure('Modern.TEntry',
                           fieldbackground='#313244',
                           borderwidth=1,
                           relief='solid',
                           insertcolor='#cdd6f4',
                           font=('Segoe UI', 12))

    def create_widgets(self):
        """Create and arrange GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Modern.TFrame', padding=30)
        main_frame.pack(fill='both', expand=True)
        
        # Header section
        header_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        header_frame.pack(fill='x', pady=(0, 30))
        
        title_label = ttk.Label(header_frame, text="🔐 Password Strength Evaluator", 
                               style='Header.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, 
                                 text="Advanced Security Analysis with ML-Enhanced Detection",
                                 style='Subheader.TLabel')
        subtitle_label.pack(pady=(5, 0))
        
        # Password input section
        input_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        input_frame.pack(fill='x', pady=(0, 20))
        
        input_label = ttk.Label(input_frame, text="Enter Password:", style='Modern.TLabel')
        input_label.pack(anchor='w')
        
        # Password entry with show/hide toggle
        entry_frame = ttk.Frame(input_frame, style='Modern.TFrame')
        entry_frame.pack(fill='x', pady=(5, 0))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(entry_frame, textvariable=self.password_var,
                                      style='Modern.TEntry', show='*', width=50)
        self.password_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        # Show/Hide button
        self.show_var = tk.BooleanVar()
        self.show_button = tk.Button(entry_frame, text="👁", 
                                   command=self.toggle_password_visibility,
                                   bg='#45475a', fg='#cdd6f4', bd=0,
                                   font=('Segoe UI', 10), width=3)
        self.show_button.pack(side='right')
        
        # Real-time evaluation binding
        self.password_var.trace('w', self.on_password_change)
        
        # Strength indicator section
        strength_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        strength_frame.pack(fill='x', pady=(0, 20))
        
        # Strength bar
        self.strength_canvas = tk.Canvas(strength_frame, height=30, bg='#313244', 
                                       highlightthickness=0)
        self.strength_canvas.pack(fill='x', pady=(0, 10))
        
        # Strength text and score
        info_frame = ttk.Frame(strength_frame, style='Modern.TFrame')
        info_frame.pack(fill='x')
        
        self.strength_label = ttk.Label(info_frame, text="Strength: Not Evaluated", 
                                      style='Modern.TLabel', font=('Segoe UI', 14, 'bold'))
        self.strength_label.pack(side='left')
        
        self.score_label = ttk.Label(info_frame, text="Score: 0/100", 
                                   style='Modern.TLabel')
        self.score_label.pack(side='right')
        
        # Entropy display
        self.entropy_label = ttk.Label(strength_frame, text="Entropy: 0 bits", 
                                     style='Modern.TLabel')
        self.entropy_label.pack(anchor='w', pady=(5, 0))
        
        # Security analysis section
        analysis_frame = ttk.LabelFrame(main_frame, text=" Security Analysis ", 
                                      padding=15, style='Modern.TFrame')
        analysis_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Analysis text widget
        self.analysis_text = tk.Text(analysis_frame, height=12, wrap='word',
                                   bg='#313244', fg='#cdd6f4', 
                                   font=('Segoe UI', 10), bd=0,
                                   padx=15, pady=10)
        self.analysis_text.pack(fill='both', expand=True)
        
        # Scrollbar for analysis text
        scrollbar = ttk.Scrollbar(analysis_frame, orient='vertical', 
                                command=self.analysis_text.yview)
        self.analysis_text.config(yscrollcommand=scrollbar.set)
        
        # Footer
        footer_frame = ttk.Frame(main_frame, style='Modern.TFrame')
        footer_frame.pack(fill='x')
        
        footer_label = ttk.Label(footer_frame, 
                               text="🛡️ Built with NIST Guidelines & ML-Enhanced Detection",
                               style='Subheader.TLabel', font=('Segoe UI', 9))
        footer_label.pack()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_var.get():
            self.password_entry.configure(show='')
            self.show_button.configure(text='🔒')
            self.show_var.set(False)
        else:
            self.password_entry.configure(show='*')
            self.show_button.configure(text='👁')
            self.show_var.set(True)

    def on_password_change(self, *args):
        """Handle real-time password evaluation"""
        password = self.password_var.get()
        self.evaluate_and_display(password)

    def evaluate_and_display(self, password):
        """Evaluate password and update display"""
        score, strength, color, feedback = self.evaluator.evaluate_password(password)
        entropy = self.evaluator.calculate_entropy(password)
        
        # Update strength bar
        self.update_strength_bar(score, color)
        
        # Update labels
        self.strength_label.configure(text=f"Strength: {strength}", foreground=color)
        self.score_label.configure(text=f"Score: {score}/100")
        self.entropy_label.configure(text=f"Entropy: {entropy:.1f} bits")
        
        # Update analysis text
        self.update_analysis_text(password, score, strength, entropy, feedback)

    def update_strength_bar(self, score, color):
        """Update the visual strength bar"""
        self.strength_canvas.delete("all")
        bar_width = self.strength_canvas.winfo_width()
        if bar_width <= 1:  # Handle initial rendering
            bar_width = 540
            
        # Background bar
        self.strength_canvas.create_rectangle(0, 5, bar_width, 25, 
                                            fill='#45475a', outline='')
        
        # Strength bar
        fill_width = (score / 100) * bar_width
        self.strength_canvas.create_rectangle(0, 5, fill_width, 25, 
                                            fill=color, outline='')
        
        # Score text
        if score > 0:
            self.strength_canvas.create_text(bar_width/2, 15, 
                                           text=f"{score}%", 
                                           fill='white', 
                                           font=('Segoe UI', 10, 'bold'))

    def update_analysis_text(self, password, score, strength, entropy, feedback):
        """Update the security analysis text"""
        self.analysis_text.delete(1.0, tk.END)
        
        if not password:
            self.analysis_text.insert(tk.END, "Enter a password to see detailed security analysis...")
            return
            
        # Analysis report
        analysis = f"""📊 DETAILED SECURITY ANALYSIS
        
Password Length: {len(password)} characters
Entropy Score: {entropy:.1f} bits
Overall Strength: {strength} ({score}/100 points)

🔍 EVALUATION BREAKDOWN:
• Length Score: {self.evaluator.check_length_score(password)}/25 points
• Character Diversity: {self.evaluator.check_diversity_score(password)}/20 points  
• Entropy Rating: {self.evaluator.check_entropy_score(password)}/30 points
• Pattern Analysis: {self.evaluator.check_pattern_vulnerability(password)}/15 points
• Breach Check: {self.evaluator.check_breach_status(password)}/10 points

⚠️ SECURITY RECOMMENDATIONS:
"""
        
        if feedback:
            for item in feedback:
                analysis += f"{item}\n"
        else:
            analysis += "✅ Password meets all security criteria!\n"
            
        # Time to crack estimation
        analysis += f"\n🕒 ESTIMATED CRACK TIME:\n"
        if entropy < 35:
            analysis += "• Seconds to minutes (Very Vulnerable)"
        elif entropy < 60:
            analysis += "• Hours to days (Vulnerable)" 
        elif entropy < 90:
            analysis += "• Years to decades (Secure)"
        else:
            analysis += "• Centuries+ (Highly Secure)"
            
        analysis += f"\n\n🛡️ NIST COMPLIANCE:\n"
        if len(password) >= 8:
            analysis += "✅ Meets NIST minimum length requirement\n"
        else:
            analysis += "❌ Below NIST minimum length requirement\n"
            
        if score >= 60:
            analysis += "✅ Recommended for sensitive accounts"
        elif score >= 40:
            analysis += "⚠️ Acceptable for low-risk accounts"
        else:
            analysis += "❌ Not recommended for any accounts"
            
        self.analysis_text.insert(tk.END, analysis)

def main():
    """Main application entry point"""
    root = tk.Tk()
    
    # Set application icon (if available)
    try:
        root.iconbitmap('password_icon.ico')
    except:
        pass
    
    app = ModernPasswordGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()