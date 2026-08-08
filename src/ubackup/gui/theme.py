APP_QSS = r"""
QWidget { background: #0f141b; color: #e7edf5; font-size: 13px; }
QMainWindow { background: #0b1016; }
QFrame#Sidebar { background: #111923; border-right: 1px solid #273242; }
QLabel#Title { font-size: 22px; font-weight: 700; }
QLabel#Muted { color: #8fa0b5; }
QLabel#CardValue { font-size: 24px; font-weight: 700; }
QFrame#Card { background: #151e29; border: 1px solid #283544; border-radius: 12px; }
QPushButton { background: #202c3a; border: 1px solid #344559; padding: 8px 12px; border-radius: 8px; }
QPushButton:hover { background: #293849; }
QPushButton:pressed { background: #18222d; }
QPushButton#Primary { background: #2f6fed; border-color: #3f7cf0; color: white; font-weight: 600; }
QPushButton#Danger { background: #5b2530; border-color: #854052; }
QPushButton#Nav { text-align: left; padding: 10px 14px; border: none; background: transparent; }
QPushButton#Nav:checked { background: #1b2734; border-left: 3px solid #5f8ef5; border-radius: 0; }
QTreeWidget, QTableWidget, QListWidget, QTextEdit { background: #101720; alternate-background-color: #131c27; border: 1px solid #273443; border-radius: 8px; }
QHeaderView::section { background: #18222d; color: #b9c6d7; border: 0; padding: 8px; }
QTreeWidget::item, QTableWidget::item, QListWidget::item { padding: 5px; }
QTreeWidget#FilesystemTree::item { padding: 9px 6px; min-height: 32px; }
QTreeWidget::item:selected, QTableWidget::item:selected, QListWidget::item:selected { background: #294a78; }
QLineEdit, QComboBox { background: #121a24; border: 1px solid #334355; border-radius: 7px; padding: 7px; }
QProgressBar { background: #121a24; border: 1px solid #334355; border-radius: 6px; text-align: center; }
QProgressBar::chunk { background: #3d78e8; border-radius: 5px; }
QTabWidget::pane { border: 1px solid #273443; border-radius: 8px; }
QTabBar::tab { background: #151e29; padding: 8px 12px; }
QTabBar::tab:selected { background: #26364a; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator, QTreeView::indicator, QTableView::indicator, QListView::indicator {
    width: 16px; height: 16px; border: 2px solid #a9bdd2; border-radius: 4px; background: #0a0f15;
}
QCheckBox::indicator:hover, QTreeView::indicator:hover, QTableView::indicator:hover, QListView::indicator:hover {
    border-color: #d6e4f2; background: #162131;
}
QCheckBox::indicator:checked, QTreeView::indicator:checked, QTableView::indicator:checked, QListView::indicator:checked {
    border-color: #8db1ff; background: #3d78e8;
}
QCheckBox::indicator:indeterminate, QTreeView::indicator:indeterminate, QTableView::indicator:indeterminate, QListView::indicator:indeterminate {
    border-color: #b7a9ff; background: #725ce6;
}
QCheckBox::indicator:disabled, QTreeView::indicator:disabled, QTableView::indicator:disabled, QListView::indicator:disabled {
    border-color: #536273; background: #202833;
}
QToolTip { background: #202b39; color: white; border: 1px solid #40526a; }
"""
