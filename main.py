from tkinter import Tk
from gui import CryptoGuardGUI

def main():
    root = Tk()
    app = CryptoGuardGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()