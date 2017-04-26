import unittest
from vc_diss_cruncher import *


class AuthTests(unittest.TestCase):

    def testGoodAuth(self):
        token = get_access_token(service_catalogue['ops'], "test1", "pass", "cruncher1")
        self.assertIsNotNone(token)

    def testBadAuth(self):
        token = get_access_token(service_catalogue['ops'], "**", "pass", "cruncher1")
        self.assertIsNone(token)

    def testBadPass(self):
        token = get_access_token(service_catalogue['ops'], "test1", "**", "cruncher1")
        self.assertIsNone(token)

    def testLockedAccount(self):
        token = get_access_token(service_catalogue['ops'], "test1", "**", "cruncher1")#invalid
        token = get_access_token(service_catalogue['ops'], "test1", "**", "cruncher1")#invalid
        token = get_access_token(service_catalogue['ops'], "test1", "**", "cruncher1")#invalid

        token = get_access_token(service_catalogue['ops'], "test1", "pass", "cruncher1")  #valid: locked by now

        self.assertIsNone(token)

class GetInputTests(unittest.TestCase):

    def testGetInput(self):
        access_token = get_access_token(service_catalogue['ops'], "test2", "pass", "cruncher1")
        new_input_response = get_input(service_catalogue['work-out'], access_token).read()
        self.assertIsNotNone(new_input_response)

    def testGetInputBadAuth(self):
        try:
            new_input_response = get_input(service_catalogue['work-out'], "**BADTOKEN**").read()
            self.fail("Should've errored")
        except urllib2.HTTPError as err:
            self.assertEqual(403, err.code)



class ValidateCodeTests(unittest.TestCase):

    def testValidateCode(self):
        test_string="7fa8d8b1-f64f-4168-86ae-9f7c5164e68f"
        known_hash="3c80760d1af20c0e86d2ab9165a6b2e9"


        validated=validate_code(known_hash, test_string)
        self.assertTrue(validated)

    def testInvalidateCode(self):
        test_string="7fa8d8b1-f64f-4168-86ae-9f7c5164e68f"
        known_invalid_hash="*****"


        validated=validate_code(known_invalid_hash, test_string)
        self.assertFalse(validated)





class IntegrationTests(unittest.TestCase):

    def testBasicRun(self):
        #Test that does one whole "auth-get input-get code-validate-crunch-post result" loop

        access_token = get_access_token(service_catalogue['ops'], "test2", "pass", "cruncher2")
        self.assertIsNotNone(access_token)


        new_input_response = get_input(service_catalogue['work-out'], access_token).read()
        new_input_response_json = json.loads(new_input_response)

        code_hash = new_input_response_json['codeHash']
        input_value = new_input_response_json['input']

        self.assertIsNotNone(code_hash)
        self.assertIsNotNone(input_value)

        if not os.path.isfile(code_hash + ".py"):
            get_code(service_catalogue['work-out'], code_hash, access_token)
            self.assertTrue(os.path.isfile(code_hash + ".py"))
        else:
            self.assertTrue(os.path.isfile(code_hash + ".py"))

            if (validate_code(code_hash, open(code_hash + ".py", "r").read())):

                result = run_algorithm_with_input(code_hash, input_value)
                self.assertTrue(bool(result))

                if result is not None:
                    response = post_result(service_catalogue['results-in'], input_value, result, access_token)
                    self.assertEqual(200, response)

            else:
                get_code(service_catalogue['work-out'], code_hash, access_token)


service_catalogue_url = "http://localhost:8080/serviceCatalogue"

service_catalogue = json.loads(urllib2.urlopen(service_catalogue_url).read())



def main():
    unittest.main()



if __name__ == "__main__":
    main()