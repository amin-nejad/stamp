#include <iostream>
#include <openssl/sha.h>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <fstream>
#include <string>
#include "stamp.h"

using namespace std;

/* You are pre-supplied with the functions below. Add your own 
   function definitions to the end of this file. */

// helper function for internal use only
// transforms raw binary hash value into human-friendly hexademical form
void convert_hash(const unsigned char *str, char *output, int hash_length) {
  char append[16];
  strcpy (output, "");
  for (int n=0; n<hash_length; n++) {
    sprintf(append,"%02x",str[n]);
    strcat(output, append);
  }
}

// pre-supplied helper function
// generates the SHA1 hash of input string text into output parameter digest
// ********************** IMPORTANT **************************
// ---> remember to include -lcrypto in your linking step <---
// ---> so that the definition of the function SHA1 is    <---
// ---> included in your program                          <---
// ***********************************************************
void text_to_SHA1_digest(const char *text, char *digest) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1( (const unsigned char *) text, strlen(text), hash);
  convert_hash(hash, digest, SHA_DIGEST_LENGTH);
}

/* add your function definitions here */

int ACCEPTABLE_NUMBER_OF_ZEROS = 5;
long MAX_NUMBER_OF_ATTEMPTS = 10000000;
int MAX_HASH_HEADER_LENGTH = 42;

int leading_zeros(string digest){

  int count = 0;
  bool leading = true;
  
  for (unsigned i =0; i < digest.length(); i++){

    // perform character checks
    if (!isalnum(digest[i])){
      return -1;
    }

    if (digest[i] > 'f'){
      return -1;
    }

    if (digest[i] == '0' && i == 0){
      count++;
    } else if (digest [i] == '0' && digest[i-1] == '0' && leading == true){
      count++;
    } else {
      leading = false;
    }
  }

  return count;
}

bool file_to_SHA1_digest(string filename, char* digest){

  // essentially a wrapper for the text_to_SHA1_digest function
  // allowing the user to just supply the filename
  
  fstream input_stream;
  string text;
  char ch;

  input_stream.open(filename);

  if (input_stream.fail()){
    strcpy(digest, "error");
    return false;
  }

  input_stream.get(ch);
  
  while (!input_stream.eof()){
    text += ch;
    input_stream.get(ch);
  }
  
  text_to_SHA1_digest(text.c_str(), digest);
  
  return true;
}

// please note this function takes a while to iterate through the possibilities
// until it finds a digest that begins with 5 zeros so please be patient
bool make_header(const string &recipient, const string &filename, char* header){

  int counter = 0;
  string header_digest_str;  
  char header_digest[41];
  string temp_header;
  char body_digest[41];
  string header_str = header;

  file_to_SHA1_digest(filename, body_digest);
  temp_header += recipient + ":" + body_digest + ":" + to_string(counter);

  while (counter < (MAX_NUMBER_OF_ATTEMPTS + 1) &&
	 leading_zeros(header_digest_str) < ACCEPTABLE_NUMBER_OF_ZEROS){
    
    header_str = temp_header;
    header_str = header_str.substr(0, recipient.length() + MAX_HASH_HEADER_LENGTH);
    temp_header = header_str + to_string(counter);

    text_to_SHA1_digest(temp_header.c_str(), header_digest);
    header_digest_str = header_digest;
    counter++;
  }
  
  strcpy(header, temp_header.c_str());
  
  if (counter <= MAX_NUMBER_OF_ATTEMPTS &&
      leading_zeros(header_digest) >= ACCEPTABLE_NUMBER_OF_ZEROS){
    return true;
  }

  return false;
}

MessageStatus check_header(string email_address,
			   string header,
			   string filename){

  // confirm header is in correct format i.e. 3 fields separated by ':'

  unsigned colon_count = 0;
  
  for (unsigned i = 0; i < header.length(); i++){

    if (header[i] == ':'){
      if (i == 0 || i == header.length() -1){
	return INVALID_HEADER;
      }
      colon_count++;
    }
  }
  
  if (colon_count != 2){
    return INVALID_HEADER;
  } 
  
  // confirm recipient is correct

  string header_recipient = header.substr(0, header.find_first_of(":"));
  if (email_address != header_recipient){
    return WRONG_RECIPIENT;
  }

  // confirm SHA1 message digest is a match

  string message_digest =
    header.substr(header.find_first_of(":") + 1,
		  header.find_last_of(":") - header.find_first_of(":") - 1);

  char message_digest_2[41];
  file_to_SHA1_digest(filename, message_digest_2);

  if (strcmp(message_digest.c_str(), message_digest_2) != 0){
    return INVALID_MESSAGE_DIGEST;
  }  

  // confirm that the SHA1 digest of the header is an acceptable header (5 zeros)

  char header_digest[41];
  string header_digest_str;
  
  text_to_SHA1_digest(header.c_str(), header_digest);

  header_digest_str = header_digest;

  if (leading_zeros(header_digest_str) < 5){
    return INVALID_HEADER_DIGEST;
  }  
  
  // default
  return VALID_EMAIL;
}
