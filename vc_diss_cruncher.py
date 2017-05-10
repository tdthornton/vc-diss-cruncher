import hashlib
import json
import os
import urllib2
import sys
import time
from subprocess import call

# The source code for vc-diss-cruncher, the cruncher client for vc-diss.
# To run: vc-diss-cruncher <user> <pass> <cruncher-name>
# Detailed guides can be found at https://vc-diss.appspot.com/about

#The first step: authenticate. Send credentials to the server.
#The server returns to us a token to store and use to authorise all further calls for two hours


def get_access_token(opsurl, user, password, crunchername):
    try:

        authRequest = {}
        authRequest["username"] = user
        authRequest["password"] = password

        req = urllib2.Request(opsurl + "auth", #url
                              json.dumps(authRequest), #payload
                              {'Content-Type': 'application/json',
                               "crunchername": crunchername} #cruncher name: optionally unique ID for each crunching VM
                              )

        resp = urllib2.urlopen(req)
        token = resp.read()

        print_with_details('Successfully authenticated. Welcome, ' + user)
        return token

    except urllib2.HTTPError as err:
        print_with_details("Authentication failure: " + str(err.code) + " (" + str(err.reason) + ")")
    except urllib2.URLError as err:
        print_with_details("Authentication faulire: " + str(err.reason))


#The second step: get an input to run against the algorithm.
#We ask the server for a new input, authenticating with the acquired token.
def get_input(workouturl, auth):

        req = urllib2.Request(workouturl, headers={"X-Auth-Token": auth})

        return urllib2.urlopen(req)






#Once we have confirmed the code is safe, we run the new input against it, and report back on the result.
def run_algorithm_with_input(md5, input):
    try:
        output_file_name = 'output.txt'

        #call the algorithm
        sts = call(md5 + ".py " + str(input) + " > " + output_file_name, shell=True)

        #the algorithm saves its output (the result) to a file, whose contents we want back.
        file = open(output_file_name, "r")
        result_string = file.read()
        file.close()

        #then we delete the file before reporting the result, to prevent its reuse.
        os.remove(file.name)

        return result_string

    except Exception as e:
        print_with_details('Error running algorithm. File structure potentially tampered with.')



#Simple checksum validation against downloaded code.
def validate_code(md5, resp):
    m = hashlib.md5()
    m.update(resp)

    return m.hexdigest()==md5



#If we do not possess the latest algorithm, we must download it.
def get_code(workouturl, md5, auth):


    #Retrieving the input has given us the checksum of the code that we need, so we ask the server for the code with it.
    dict = {}
    dict["md5"] = md5

    data = json.dumps(dict)

    #call the server
    req = urllib2.Request(workouturl, data, {'Content-Type': 'application/json', "X-Auth-Token": auth})
    resp = urllib2.urlopen(req).read()


    print_with_details('Retrieved latest code.')
    with open(md5 + ".py", "w") as text_file:
        text_file.write(resp)


    if validate_code(md5, resp):
        print_with_details('New code successfully validated. Saving to algorithm file.')
    else:
        print_with_details('New code failed validation. Retrying.')
        get_code(workouturl, md5, auth)



#Once the input has been run against the algorithm, we must post the result back to the server.
#If the result is later verified, we will be credited for this result.
def post_result(resultsinurl, input, result, auth):


    dict = {}
    dict["input"] = input
    dict["result"] = result

    data = json.dumps(dict)
    request = urllib2.Request(resultsinurl, data, {'Content-Type': 'application/json', "X-Auth-Token": auth})
    response = urllib2.urlopen(request)
    return response.code


def print_with_details(message):
    print str(message) #incase in future it becomes worth adding crunchername, etc to the input




def main():

    user = sys.argv[1]
    password = sys.argv[2]
    crunchername = sys.argv[3]

    print_with_details('Welcome to vc-diss. Thank you for crunching with us today.')
    print_with_details('You can check your cruncher fleet, and pause it, at https://vc-diss.appspot.com')
    print_with_details('')
    print_with_details('')
    print_with_details('')
    print_with_details('')

    if user is None or password is None or crunchername is None:
        print_with_details('Error: Invalid inputs.')
    else:

        print_with_details('Getting vc-diss service catalogue from the server.')
        service_catalogue_url="https://vc-diss.appspot.com/servicecatalogue"

        service_catalogue = json.loads(urllib2.urlopen(service_catalogue_url).read())

        print_with_details('Trying to authenticate as ' + user)
        access_token = get_access_token(service_catalogue['ops'], user, password, crunchername)



        while True:

            try:
                print_with_details('Calling server for new input...')
                new_input_response = get_input(service_catalogue['work-out'], access_token).read()

                new_input_response_json = json.loads(new_input_response) #unpack json from server

                code_hash = new_input_response_json['codeHash'] #checksum to validate any code with before running it.
                input_value = new_input_response_json['input'] #value to run against code ("crunch")

                print_with_details('Successfully retrieved next input to crunch.')

                if not os.path.isfile(code_hash + ".py"): #if there isn't already a python file with the name of the checksum we were sent...
                    print_with_details('Latest algorithm code not found locally. Downloading...')
                    get_code(service_catalogue['work-out'], code_hash, access_token)



                if (validate_code(code_hash, open(code_hash + ".py", "r").read())): #if the code in the file still matches the checksum we were sent.

                    print_with_details('Existing code successfully validated. Crunching time...')
                    result = run_algorithm_with_input(code_hash, input_value)

                    if result is not None:
                        print_with_details('Successfully crunched input. Posting back to server...')
                        post_result(service_catalogue['results-in'], input_value, result, access_token)
                        print_with_details('Posted result for input. Another successful crunch!')
                    else:
                        print_with_details('Error loading result of crunching. Will try with new input...')


                    print_with_details('')
                    print_with_details('')

                else:
                    print_with_details('Potential security error: code found, but failed validation. Will try to update with safe code.')
                    get_code(service_catalogue['work-out'], code_hash, access_token)


            except urllib2.HTTPError as err:
                if err.code == 409:
                    print_with_details('You have paused crunching. Entering idle mode for 30 seconds.')
                    time.sleep(30)
                if err.code == 403:
                    print_with_details('Authentication error: refreshing token.')
                    access_token = get_access_token(service_catalogue['ops'], user, password, crunchername)
                else :
                    print_with_details("HTTP ERROR " + str(err.code) + ": " + str(err.reason))

            except urllib2.URLError as err:
                print_with_details('URL ERROR' + str(err.reason))


if __name__ == "__main__":
    main()



