#PASWORD CHECKER
#DEFINE RULES
#CHECKS IF PASSWORD IS GOOD STRENGTH OR BAD STRENGTH


from password_strength import PasswordPolicy
from password_strength import PasswordStats




print("PASSWORDCHECKER")
print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
print(
    'Password Rules: Length=8 :Uppercase=2,Numbers=2,2 digits special=2,2 special characters nonletters=2,2 non-letter characters (digits, specials, anything)')
print('***************************************************************************')



policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=2,  # need min. 2 uppercase letters
    numbers=2,  # need min. 2 digits
    special=2,  # need min. 2 special characters
    nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)

)

PassChecker = input("Enter Password:")
z = policy.test(PassChecker)

check = (len(z))

if check > 0:
    print("Password is BAD Strength")

elif check == 0:
    print("Password is GOOD Strength")
