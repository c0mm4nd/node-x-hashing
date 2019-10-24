#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "blake.h"
    #include "c11.h"
    #include "fresh.h"
    #include "fugue.h"
    #include "groestl.h"
    #include "hefty1.h"
    #include "keccak.h"
    #include "lbry.h"
    #include "nist5.h"
    #include "quark.h"
    #include "qubit.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "sha1.h"
    #include "sha256d.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "x11.h"
    #include "x13.h"
    #include "x15.h"
    #include "x16r.h"
    #include "x16rv2.h"
    #include "neoscrypt.h"
}

using namespace node;
using namespace v8;
// using namespace v8::Value;

// NODE_MAJOR_VERSION >=13

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)

#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)

#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));

#define RETURN_EXCEPT(msg) \
    do { \
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg).ToLocalChecked())); \
        return; \
    } while (0)


#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
	Local<Context> context = isolate->GetCurrentContext(); \
 \
    Local<Object> target = args[0]->ToObject(context).ToLocalChecked(); \
 \
    if(!Buffer::HasInstance(target)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(target); \
    char output[32]; \
 \
    uint32_t input_len = Buffer::Length(target); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}


// void bcrypt(const FunctionCallbackInfo<Value>& args) {
// 	DECLARE_SCOPE;
// 	if (args.Length() < 1) RETURN_EXCEPT("You must provide one argument.");
// 	Local<Context> context = isolate->GetCurrentContext();
// 	Local<Object> target = args[0]->ToObject(context).ToLocalChecked();
// 	if (!Buffer::HasInstance(target)) {
// 		do {
// 			&isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, ("Argument should be a buffer object.")).ToLocalChecked())); \
// 				return;
// 		} while (0);
// 	};
// 	char* input = Buffer::Data(target);
// 	char output[32];
// 	uint32_t input_len = Buffer::Length(target);
// 	bcrypt_hash(input, output, input_len);
// 	SET_BUFFER_RETURN(output, 32);
// }

DECLARE_CALLBACK(bcrypt, bcrypt_hash, 32);
DECLARE_CALLBACK(blake, blake_hash, 32);
DECLARE_CALLBACK(c11, c11_hash, 32);
DECLARE_CALLBACK(fresh, fresh_hash, 32);
DECLARE_CALLBACK(fugue, fugue_hash, 32);
DECLARE_CALLBACK(groestl, groestl_hash, 32);
DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
DECLARE_CALLBACK(hefty1, hefty1_hash, 32);
DECLARE_CALLBACK(keccak, keccak_hash, 32);
DECLARE_CALLBACK(lbry, lbry_hash, 32);
DECLARE_CALLBACK(nist5, nist5_hash, 32);
DECLARE_CALLBACK(quark, quark_hash, 32);
DECLARE_CALLBACK(qubit, qubit_hash, 32);
DECLARE_CALLBACK(sha1, sha1_hash, 32);
DECLARE_CALLBACK(sha256d, sha256d_hash, 32);
DECLARE_CALLBACK(shavite3, shavite3_hash, 32);
DECLARE_CALLBACK(skein, skein_hash, 32);
DECLARE_CALLBACK(x11, x11_hash, 32);
DECLARE_CALLBACK(x13, x13_hash, 32);
DECLARE_CALLBACK(x15, x15_hash, 32);
DECLARE_CALLBACK(x16r, x16r_hash, 32);
DECLARE_CALLBACK(x16rv2, x16rv2_hash, 32);


DECLARE_FUNC(scrypt) {
   DECLARE_SCOPE;

   if (args.Length() < 3)
       RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");

   Local<Context> context = isolate->GetCurrentContext();
   Local<Object> target = args[0]->ToObject(context).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nValue = args[1]->Uint32Value(context).ToChecked();
   unsigned int rValue = args[2]->Uint32Value(context).ToChecked();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(neoscrypt) {
   DECLARE_SCOPE;

   if (args.Length() < 2)
       RETURN_EXCEPT("You must provide two arguments");

   Local<Context> context = isolate->GetCurrentContext();
   Local<Object> target = args[0]->ToObject(context).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   // unsigned int nValue = args[1]->Uint32Value();
   // unsigned int rValue = args[2]->Uint32Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   neoscrypt(input, output, 0);

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(scryptn) {
   DECLARE_SCOPE;

   if (args.Length() < 2)
       RETURN_EXCEPT("You must provide buffer to hash and N factor.");

   Local<Context> context = isolate->GetCurrentContext();
   Local<Object> target = args[0]->ToObject(context).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nFactor = args[1]->Uint32Value(context).ToChecked();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(scryptjane) {
    DECLARE_SCOPE;

    if (args.Length() < 5)
        RETURN_EXCEPT("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

	Local<Context> context = isolate->GetCurrentContext();
	Local<Object> target = args[0]->ToObject(context).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("First should be a buffer object.");

    int timestamp = args[1]->Int32Value(context).ToChecked();
    int nChainStartTime = args[2]->Int32Value(context).ToChecked();
    int nMin = args[3]->Int32Value(context).ToChecked();
    int nMax = args[4]->Int32Value(context).ToChecked();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    SET_BUFFER_RETURN(output, 32);
}

DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "c11", c11);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "lbry", lbry);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "scryptjane", scryptjane);
    NODE_SET_METHOD(exports, "scryptn", scryptn);
    NODE_SET_METHOD(exports, "sha1", sha1);
    NODE_SET_METHOD(exports, "sha256d", sha256d);
    NODE_SET_METHOD(exports, "shavite3", shavite3);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "x15", x15);
    NODE_SET_METHOD(exports, "x16r", x16r);
    NODE_SET_METHOD(exports, "x16rv2", x16rv2);
    NODE_SET_METHOD(exports, "neoscrypt", neoscrypt);
}

NODE_MODULE(multihashing, init)
