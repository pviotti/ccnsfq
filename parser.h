// parser.h
//

#ifndef LZZ_parser_h
#define LZZ_parser_h
#define LZZ_INLINE inline

#include <linux/kernel.h>	
#include <linux/module.h>

#include <linux/string.h>
#include <linux/slab.h>		// for kcalloc(), kmalloc()...
#include <linux/ctype.h>	// for isalpha()...

enum ccn_tt
{
  CCN_EXT,
  CCN_TAG,
  CCN_DTAG,
  CCN_ATTR,
  CCN_DATTR,
  CCN_BLOB,
  CCN_UDATA,
  CCN_NO_TOKEN
};
enum ccn_decoder_state
{
  CCN_DSTATE_INITIAL = 0,
  CCN_DSTATE_NEWTOKEN,
  CCN_DSTATE_NUMVAL,
  CCN_DSTATE_UDATA,
  CCN_DSTATE_TAGNAME,
  CCN_DSTATE_ATTRNAME,
  CCN_DSTATE_BLOB,
  CCN_DSTATE_ERR_OVERFLOW = -1,
  CCN_DSTATE_ERR_ATTR = -2,
  CCN_DSTATE_ERR_CODING = -3,
  CCN_DSTATE_ERR_NEST = -4,
  CCN_DSTATE_ERR_BUG = -5
};
enum ccn_parsed_interest_offsetid
{
  CCN_PI_B_Name,
  CCN_PI_B_Component0,
  CCN_PI_B_LastPrefixComponent,
  CCN_PI_E_LastPrefixComponent,
  CCN_PI_E_ComponentLast = CCN_PI_E_LastPrefixComponent,
  CCN_PI_E_Name,
  CCN_PI_B_MinSuffixComponents,
  CCN_PI_E_MinSuffixComponents,
  CCN_PI_B_MaxSuffixComponents,
  CCN_PI_E_MaxSuffixComponents,
  CCN_PI_B_PublisherID,
  CCN_PI_B_PublisherIDKeyDigest,
  CCN_PI_E_PublisherIDKeyDigest,
  CCN_PI_E_PublisherID,
  CCN_PI_B_Exclude,
  CCN_PI_E_Exclude,
  CCN_PI_B_ChildSelector,
  CCN_PI_E_ChildSelector,
  CCN_PI_B_AnswerOriginKind,
  CCN_PI_E_AnswerOriginKind,
  CCN_PI_B_Scope,
  CCN_PI_E_Scope,
  CCN_PI_B_Nonce,
  CCN_PI_E_Nonce,
  CCN_PI_B_OTHER,
  CCN_PI_E_OTHER,
  CCN_PI_E
};
enum ccn_parsed_content_object_offsetid
{
  CCN_PCO_B_Signature,
  CCN_PCO_B_DigestAlgorithm,
  CCN_PCO_E_DigestAlgorithm,
  CCN_PCO_B_Witness,
  CCN_PCO_E_Witness,
  CCN_PCO_B_SignatureBits,
  CCN_PCO_E_SignatureBits,
  CCN_PCO_E_Signature,
  CCN_PCO_B_Name,
  CCN_PCO_B_Component0,
  CCN_PCO_E_ComponentN,
  CCN_PCO_E_ComponentLast = CCN_PCO_E_ComponentN,
  CCN_PCO_E_Name,
  CCN_PCO_B_SignedInfo,
  CCN_PCO_B_PublisherPublicKeyDigest,
  CCN_PCO_E_PublisherPublicKeyDigest,
  CCN_PCO_B_Timestamp,
  CCN_PCO_E_Timestamp,
  CCN_PCO_B_Type,
  CCN_PCO_E_Type,
  CCN_PCO_B_FreshnessSeconds,
  CCN_PCO_E_FreshnessSeconds,
  CCN_PCO_B_FinalBlockID,
  CCN_PCO_E_FinalBlockID,
  CCN_PCO_B_KeyLocator,
  CCN_PCO_B_Key_Certificate_KeyName,
  CCN_PCO_B_KeyName_Name,
  CCN_PCO_E_KeyName_Name,
  CCN_PCO_B_KeyName_Pub,
  CCN_PCO_E_KeyName_Pub,
  CCN_PCO_E_Key_Certificate_KeyName,
  CCN_PCO_E_KeyLocator,
  CCN_PCO_E_SignedInfo,
  CCN_PCO_B_Content,
  CCN_PCO_E_Content,
  CCN_PCO_E
};
enum ccn_dtag
{
  CCN_DTAG_Any = 13,
  CCN_DTAG_Name = 14,
  CCN_DTAG_Component = 15,
  CCN_DTAG_Certificate = 16,
  CCN_DTAG_Collection = 17,
  CCN_DTAG_CompleteName = 18,
  CCN_DTAG_Content = 19,
  CCN_DTAG_SignedInfo = 20,
  CCN_DTAG_ContentDigest = 21,
  CCN_DTAG_ContentHash = 22,
  CCN_DTAG_Count = 24,
  CCN_DTAG_Header = 25,
  CCN_DTAG_Interest = 26,
  CCN_DTAG_Key = 27,
  CCN_DTAG_KeyLocator = 28,
  CCN_DTAG_KeyName = 29,
  CCN_DTAG_Length = 30,
  CCN_DTAG_Link = 31,
  CCN_DTAG_LinkAuthenticator = 32,
  CCN_DTAG_NameComponentCount = 33,
  CCN_DTAG_RootDigest = 36,
  CCN_DTAG_Signature = 37,
  CCN_DTAG_Start = 38,
  CCN_DTAG_Timestamp = 39,
  CCN_DTAG_Type = 40,
  CCN_DTAG_Nonce = 41,
  CCN_DTAG_Scope = 42,
  CCN_DTAG_Exclude = 43,
  CCN_DTAG_Bloom = 44,
  CCN_DTAG_BloomSeed = 45,
  CCN_DTAG_AnswerOriginKind = 47,
  CCN_DTAG_Witness = 53,
  CCN_DTAG_SignatureBits = 54,
  CCN_DTAG_DigestAlgorithm = 55,
  CCN_DTAG_BlockSize = 56,
  CCN_DTAG_FreshnessSeconds = 58,
  CCN_DTAG_FinalBlockID = 59,
  CCN_DTAG_PublisherPublicKeyDigest = 60,
  CCN_DTAG_PublisherCertificateDigest = 61,
  CCN_DTAG_PublisherIssuerKeyDigest = 62,
  CCN_DTAG_PublisherIssuerCertificateDigest = 63,
  CCN_DTAG_ContentObject = 64,
  CCN_DTAG_WrappedKey = 65,
  CCN_DTAG_WrappingKeyIdentifier = 66,
  CCN_DTAG_WrapAlgorithm = 67,
  CCN_DTAG_KeyAlgorithm = 68,
  CCN_DTAG_Label = 69,
  CCN_DTAG_EncryptedKey = 70,
  CCN_DTAG_EncryptedNonceKey = 71,
  CCN_DTAG_WrappingKeyName = 72,
  CCN_DTAG_Action = 73,
  CCN_DTAG_FaceID = 74,
  CCN_DTAG_IPProto = 75,
  CCN_DTAG_Host = 76,
  CCN_DTAG_Port = 77,
  CCN_DTAG_MulticastInterface = 78,
  CCN_DTAG_ForwardingFlags = 79,
  CCN_DTAG_FaceInstance = 80,
  CCN_DTAG_ForwardingEntry = 81,
  CCN_DTAG_MulticastTTL = 82,
  CCN_DTAG_MinSuffixComponents = 83,
  CCN_DTAG_MaxSuffixComponents = 84,
  CCN_DTAG_ChildSelector = 85,
  CCN_DTAG_RepositoryInfo = 86,
  CCN_DTAG_Version = 87,
  CCN_DTAG_RepositoryVersion = 88,
  CCN_DTAG_GlobalPrefix = 89,
  CCN_DTAG_LocalName = 90,
  CCN_DTAG_Policy = 91,
  CCN_DTAG_Namespace = 92,
  CCN_DTAG_GlobalPrefixName = 93,
  CCN_DTAG_PolicyVersion = 94,
  CCN_DTAG_KeyValueSet = 95,
  CCN_DTAG_KeyValuePair = 96,
  CCN_DTAG_IntegerValue = 97,
  CCN_DTAG_DecimalValue = 98,
  CCN_DTAG_StringValue = 99,
  CCN_DTAG_BinaryValue = 100,
  CCN_DTAG_NameValue = 101,
  CCN_DTAG_Entry = 102,
  CCN_DTAG_ACL = 103,
  CCN_DTAG_ParameterizedName = 104,
  CCN_DTAG_Prefix = 105,
  CCN_DTAG_Suffix = 106,
  CCN_DTAG_Root = 107,
  CCN_DTAG_ProfileName = 108,
  CCN_DTAG_Parameters = 109,
  CCN_DTAG_CCNProtocolDataUnit = 17702112
};
struct ccn_charbuf
{
  size_t length;
  size_t limit;
  unsigned char * buf;
};
struct ccn_indexbuf
{
  size_t n;
  size_t limit;
  size_t * buf;
};
enum ccn_content_type
{
  CCN_CONTENT_DATA = 0x0C04C0,
  CCN_CONTENT_ENCR = 0x10D091,
  CCN_CONTENT_GONE = 0x18E344,
  CCN_CONTENT_KEY = 0x28463F,
  CCN_CONTENT_LINK = 0x2C834A,
  CCN_CONTENT_NACK = 0x34008A
};
struct ccn_skeleton_decoder
{
  ssize_t index;
  int state;
  int nest;
  size_t numval;
  size_t token_index;
  size_t element_index;
};
struct ccn_buf_decoder
{
  struct ccn_skeleton_decoder decoder;
  unsigned char const * buf;
  size_t size;
};
struct ccn_parsed_interest
{
  int magic;
  int prefix_comps;
  int min_suffix_comps;
  int max_suffix_comps;
  int orderpref;
  int answerfrom;
  int scope;
  unsigned short int (offset) [CCN_PI_E+1];
};
struct ccn_parsed_ContentObject
{
  int magic;
  enum ccn_content_type type;
  int name_ncomps;
  unsigned short int (offset) [CCN_PCO_E+1];
  unsigned char (digest) [32];
  int digest_bytes;
};
struct parsed_KeyName
{
  int Name;
  int endName;
  int PublisherID;
  int endPublisherID;
};
int ccn_parse_required_tagged_UDATA (struct ccn_buf_decoder * d, enum ccn_dtag dtag);
int ccn_parse_optional_tagged_UDATA (struct ccn_buf_decoder * d, enum ccn_dtag dtag);
struct ccn_indexbuf * ccn_indexbuf_create (void);
struct ccn_charbuf * ccn_charbuf_create (void);
size_t * ccn_indexbuf_reserve (struct ccn_indexbuf * c, size_t n);
int ccn_buf_match_dtag (struct ccn_buf_decoder * d, enum ccn_dtag dtag);
void ccn_buf_advance (struct ccn_buf_decoder * d);
int ccn_parse_nonNegativeInteger (struct ccn_buf_decoder * d);
int ccn_parse_Name (struct ccn_buf_decoder * d, struct ccn_indexbuf * components);
int ccn_parse_PublisherID (struct ccn_buf_decoder * d, struct ccn_parsed_interest * pi);
int ccn_parse_required_tagged_BLOB (struct ccn_buf_decoder * d, enum ccn_dtag dtag, int minlen, int maxlen);
int ccn_parse_optional_tagged_BLOB (struct ccn_buf_decoder * d, enum ccn_dtag dtag, int minlen, int maxlen);
void ccn_buf_check_close (struct ccn_buf_decoder * d);
int ccn_indexbuf_append_element (struct ccn_indexbuf * c, size_t v);
int ccn_buf_match_some_blob (struct ccn_buf_decoder * d);
int ccn_buf_match_blob (struct ccn_buf_decoder * d, unsigned char const * * bufp, size_t * sizep);
ssize_t ccn_skeleton_decode (struct ccn_skeleton_decoder * d, unsigned char const * p, size_t n);
struct ccn_buf_decoder * ccn_buf_decoder_start (struct ccn_buf_decoder * d, unsigned char const * buf, size_t size);
int ccn_parse_interest (unsigned char const * msg, size_t size, struct ccn_parsed_interest * interest, struct ccn_indexbuf * components);
int ccn_parse_ContentObject (unsigned char const * msg, size_t size, struct ccn_parsed_ContentObject * x, struct ccn_indexbuf * components);
int ccn_name_comp_get (unsigned char const * data, struct ccn_indexbuf const * indexbuf, unsigned int i, unsigned char const * * comp, size_t * size);
void ccn_indexbuf_destroy (struct ccn_indexbuf * * cbp);
void ccn_charbuf_destroy (struct ccn_charbuf * * cbp);
char * parse (char * buff,  int len);
#undef LZZ_INLINE
#endif
