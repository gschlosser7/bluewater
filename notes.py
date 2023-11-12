'''11/9 database still accepting logins into moneyusers table. working on hashing passwords
    with bcrypt. thoughts: do we encrypt string right away at transport from login form? 
                            do we take string literal as a variable then pass that to a new 
                            variable to encrypt? first one seems best but with possible complications
                            dehashing.
                to do: get pgadmin password out of app.py, implement bcrypt'''
'''11/10 bcrypt hashing properly. maybe change max hashing length from 80? have to NEST TO CHECK DB FOR 
                                                                    EXISTING USER n return t/f'''
