import customtkinter

customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('green')

root = customtkinter.CTk()
root.geometry('320x360')

def login():
    print('test')

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx = 60, fill='both', expand=True)

root.after(201, lambda :root.iconbitmap('C:\\Users\\...\\filename.ico'))

myfont=('System', 18)

label = customtkinter.CTkLabel(master=frame, text='optionsBot \nLogin', font=myfont)
label.pack(pady=12, padx=10)

entry1=customtkinter.CTkEntry(master=frame, placeholder_text='Username', font=myfont)
entry1.pack(pady=12, padx=10)

entry2=customtkinter.CTkEntry(master=frame, placeholder_text='Password', show='*', font=myfont)
entry2.pack(pady=12, padx = 10)

button=customtkinter.CTkButton(master=frame, text='Login', command=login, font=myfont)
button.pack(pady=12, padx=10)


checkbox = customtkinter.CTkCheckBox(master=frame, text='Remember Me', font=myfont)
checkbox.pack(pady=35, padx =12)



root.mainloop()