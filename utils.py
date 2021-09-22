import sys

def pretty_display(chaine):
    tab_chaine = chaine.split("|")
    for str in tab_chaine:
        print("\t"+str+"\n")

# catche le ctrl + c in loop
def signal_handler(signal, frame):
   pretty_display("Programm was killing thanks to a Ctrl + c.|Hoping you had fun :D ! ")
   sys.exit(0)

def display_new_message(dictionaries):
    pretty_display("MESSAGE RECU : |\tauteur : "+dictionaries['identity']+"|\traison : "+dictionaries['request_type']+"|\tmessage : "+dictionaries["message"])