/*
	CCN binary name parser	
*/

#include "parser.h"

// Definitions ==============================
#define CCN_DSTATE_PAUSE (1 << 15)
#define CCN_GET_TT_FROM_DSTATE(state) (CCN_TT_MASK & ((state) >> 16))
#define CCN_FINAL_DSTATE(state) (((state) & (CCN_DSTATE_PAUSE-1)) == 0)
#define XML(goop) ((void)0)
#define CCN_CLOSE ((unsigned char)(0))
#define CCN_TT_BITS 3
#define CCN_TT_MASK ((1 << CCN_TT_BITS) - 1)
#define CCN_MAX_TINY ((1 << (7-CCN_TT_BITS)) - 1)
#define CCN_TT_HBIT ((unsigned char)(1 << 7))
#define ELEMENT size_t

#define CCN_AOK_CS      0x1     
#define CCN_AOK_NEW     0x2     
#define CCN_AOK_DEFAULT (CCN_AOK_CS | CCN_AOK_NEW)
#define CCN_AOK_STALE   0x4     
#define CCN_AOK_EXPIRE  0x10    

// Functions =================================
static int
ccn_parse_Signature(struct ccn_buf_decoder *d, struct ccn_parsed_ContentObject *x)
{
    int res = -1;
    int i;
    struct ccn_parsed_ContentObject dummy;
    if (x == NULL)
        x = &dummy;
    for (i = CCN_PCO_B_Signature; i <= CCN_PCO_E_Signature; i++) {
        x->offset[i] = d->decoder.token_index;
    }
    if (ccn_buf_match_dtag(d, CCN_DTAG_Signature)) {
        res = d->decoder.element_index;
        ccn_buf_advance(d);
        x->offset[CCN_PCO_B_DigestAlgorithm] = d->decoder.token_index;
        ccn_parse_optional_tagged_UDATA(d, CCN_DTAG_DigestAlgorithm);
        x->offset[CCN_PCO_E_DigestAlgorithm] = d->decoder.token_index;
        x->offset[CCN_PCO_B_Witness] = d->decoder.token_index;
        ccn_parse_optional_tagged_BLOB(d, CCN_DTAG_Witness, 8, -1);
        x->offset[CCN_PCO_E_Witness] = d->decoder.token_index;
        x->offset[CCN_PCO_B_SignatureBits] = d->decoder.token_index;
        ccn_parse_required_tagged_BLOB(d, CCN_DTAG_SignatureBits, 16, -1);
        x->offset[CCN_PCO_E_SignatureBits] = d->decoder.token_index;
        ccn_buf_check_close(d);
        x->offset[CCN_PCO_E_Signature] = d->decoder.token_index;
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

int
ccn_parse_required_tagged_UDATA(struct ccn_buf_decoder *d, enum ccn_dtag dtag)
{
    int res = -1;
    if (ccn_buf_match_dtag(d, dtag)) {
        res = d->decoder.element_index;
        ccn_buf_advance(d);
        if (d->decoder.state >= 0 &&
            CCN_GET_TT_FROM_DSTATE(d->decoder.state) == CCN_UDATA)
            ccn_buf_advance(d);
        else
            d->decoder.state = -__LINE__;
        ccn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (-1);
    return(res);
}

int
ccn_parse_optional_tagged_UDATA(struct ccn_buf_decoder *d, enum ccn_dtag dtag)
{
    if (ccn_buf_match_dtag(d, dtag))
        return(ccn_parse_required_tagged_UDATA(d, dtag));
    return(-1);
}


ELEMENT *
ccn_indexbuf_reserve(struct ccn_indexbuf *c, size_t n)
{
    size_t newlim = n + c->n;
    size_t oldlim = c->limit;
    ELEMENT *buf = c->buf;
    if (newlim < n)
        return(NULL);
    if (newlim > oldlim) {
        if (2 * oldlim > newlim)
            newlim = 2 * oldlim;
        buf = krealloc(c->buf, newlim * sizeof(ELEMENT), GFP_ATOMIC);
        if (buf == NULL)
            return(NULL);
        memset(buf + oldlim, 0, (newlim - oldlim) * sizeof(ELEMENT));
        c->buf = buf;
        c->limit = newlim;
    }
    buf += c->n;
    return(buf);
}


int
ccn_buf_match_dtag(struct ccn_buf_decoder *d, enum ccn_dtag dtag)
{
    return (d->decoder.state >= 0 &&
            CCN_GET_TT_FROM_DSTATE(d->decoder.state) == CCN_DTAG &&
            d->decoder.numval == dtag);
}

void
ccn_buf_advance(struct ccn_buf_decoder *d)
{
    ccn_skeleton_decode(&d->decoder,
                        d->buf + d->decoder.index,
                        d->size - d->decoder.index);
}

int
ccn_parse_nonNegativeInteger(struct ccn_buf_decoder *d)
{
    const unsigned char *p;
    int i;
    int n;
    int val;
    int newval;
    unsigned char c;
    if (d->decoder.state < 0)
        return(d->decoder.state);
    if (CCN_GET_TT_FROM_DSTATE(d->decoder.state) == CCN_UDATA) {
        p = d->buf + d->decoder.index;
        n = d->decoder.numval;
        if (n < 1)
            return(d->decoder.state = -__LINE__);
        val = 0;
        for (i = 0; i < n; i++) {
            c = p[i];
            if ('0' <= c && c <= '9') {
                newval = val * 10 + (c - '0');
                if (newval < val)
                    return(d->decoder.state = -__LINE__);
                val = newval;
            }
            else
                return(d->decoder.state = -__LINE__);
        }
        ccn_buf_advance(d);
        return(val);
    }
    return(d->decoder.state = -__LINE__);
}


int
ccn_parse_Name(struct ccn_buf_decoder *d, struct ccn_indexbuf *components)
{
    int ncomp = 0;
    if (ccn_buf_match_dtag(d, CCN_DTAG_Name)) {
        if (components != NULL) components->n = 0;
        ccn_buf_advance(d);
        while (ccn_buf_match_dtag(d, CCN_DTAG_Component)) {
            if (components != NULL)
                ccn_indexbuf_append_element(components, d->decoder.token_index);
            ncomp += 1;
            ccn_buf_advance(d);
            if (ccn_buf_match_blob(d, NULL, NULL))
                ccn_buf_advance(d);
            ccn_buf_check_close(d);
        }
        if (components != NULL)
            ccn_indexbuf_append_element(components, d->decoder.token_index);
        ccn_buf_check_close(d);
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return(-1);
    else
        return(ncomp);
}

int
ccn_parse_PublisherID(struct ccn_buf_decoder *d, struct ccn_parsed_interest *pi)
{
    int res = -1;
    int iskey = 0;
    unsigned pubstart = d->decoder.token_index;
    unsigned keystart = pubstart;
    unsigned keyend = pubstart;
    unsigned pubend = pubstart;
    iskey = ccn_buf_match_dtag(d, CCN_DTAG_PublisherPublicKeyDigest);
    if (iskey                                                          ||
        ccn_buf_match_dtag(d, CCN_DTAG_PublisherCertificateDigest)     ||
        ccn_buf_match_dtag(d, CCN_DTAG_PublisherIssuerKeyDigest)       ||
        ccn_buf_match_dtag(d, CCN_DTAG_PublisherIssuerCertificateDigest)) {
        res = d->decoder.element_index;
        ccn_buf_advance(d);
        keystart = d->decoder.token_index;
        if (!ccn_buf_match_some_blob(d))
            return (d->decoder.state = -__LINE__);
        ccn_buf_advance(d);
        keyend = d->decoder.token_index;
        ccn_buf_check_close(d);
        pubend = d->decoder.token_index;
    }
    if (d->decoder.state < 0)
        return (d->decoder.state);
    if (pi != NULL) {
        pi->offset[CCN_PI_B_PublisherID] = pubstart;
        pi->offset[CCN_PI_B_PublisherIDKeyDigest] = keystart;
        pi->offset[CCN_PI_E_PublisherIDKeyDigest] = iskey ? keyend : keystart;
        pi->offset[CCN_PI_E_PublisherID] = pubend;
    }
    return(res);
}

int
ccn_parse_required_tagged_BLOB(struct ccn_buf_decoder *d, enum ccn_dtag dtag,
                               int minlen, int maxlen)
{
    int res = -1;
    size_t len = 0;
    if (ccn_buf_match_dtag(d, dtag)) {
        res = d->decoder.element_index;
        ccn_buf_advance(d);
        if (ccn_buf_match_some_blob(d)) {
            len = d->decoder.numval;
            ccn_buf_advance(d);
        }
        ccn_buf_check_close(d);
        if (len < minlen || (maxlen >= 0 && len > maxlen)) {
            d->decoder.state = -__LINE__;
        }
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.state < 0)
        return (d->decoder.state);
    return(res);
}

int
ccn_parse_optional_tagged_BLOB(struct ccn_buf_decoder *d, enum ccn_dtag dtag,
                               int minlen, int maxlen)
{
    if (ccn_buf_match_dtag(d, dtag))
        return(ccn_parse_required_tagged_BLOB(d, dtag, minlen, maxlen));
    return(-1);
}

void
ccn_buf_check_close(struct ccn_buf_decoder *d)
{
    if (d->decoder.state >= 0) {
        if (CCN_GET_TT_FROM_DSTATE(d->decoder.state) != CCN_NO_TOKEN)
            d->decoder.state = CCN_DSTATE_ERR_NEST;
        else
            ccn_buf_advance(d);
    }
}


int
ccn_indexbuf_append_element(struct ccn_indexbuf *c, ELEMENT v)
{
    ELEMENT *dst = ccn_indexbuf_reserve(c, 1);
    if (dst == NULL)
        return(-1);
    *dst = v;
    c->n += 1;
    return(0);
}

int
ccn_buf_match_some_blob(struct ccn_buf_decoder *d)
{
    return(d->decoder.state >= 0 &&
           CCN_GET_TT_FROM_DSTATE(d->decoder.state) == CCN_BLOB);
}

int
ccn_buf_match_blob(struct ccn_buf_decoder *d,
                   const unsigned char **bufp, size_t *sizep)
{
    if (ccn_buf_match_some_blob(d)) {
        if (bufp != NULL)
            *bufp = d->buf + d->decoder.index;
        if (sizep != NULL)
            *sizep = d->decoder.numval;
        return (1);
    }
    if (bufp != NULL)
        *bufp = d->buf + d->decoder.token_index;
    if (sizep != NULL)
        *sizep = 0;
    return(0);
}


ssize_t
ccn_skeleton_decode(struct ccn_skeleton_decoder *d,
                    const unsigned char *p, size_t n)
{
    enum ccn_decoder_state state = d->state;
    int tagstate = 0;
    size_t numval = d->numval;
    ssize_t i = 0;
    unsigned char c;
    size_t chunk;
    int pause = 0;
    if (d->state >= 0) {
        pause = d->state & CCN_DSTATE_PAUSE;
        tagstate = (d->state >> 8) & 3;
        state = d->state & 0xFF;
    }
    while (i < n) {
        switch (state) {
            case CCN_DSTATE_INITIAL:
            case CCN_DSTATE_NEWTOKEN: /* start new thing */
                d->token_index = i + d->index;
                if (tagstate > 1 && tagstate-- == 2) {
                    XML("\""); /* close off the attribute value */
                }
                if (p[i] == CCN_CLOSE) {
                    i++;
                    if (d->nest <= 0 || tagstate > 1) {
                        state = CCN_DSTATE_ERR_NEST;
                        break;
                    }
                    if (tagstate == 1) {
                        tagstate = 0;
                        XML("/>");
                    }
                    else {
                        XML("</%s>");
                    }
                    d->nest -= 1;
                    if (d->nest == 0) {
                        state = CCN_DSTATE_INITIAL;
                        n = i;
                    }
                    if (pause) {
                        state |= (((int)CCN_NO_TOKEN) << 16);
                        n = i;
                    }
                    break;
                }
                numval = 0;
                state = CCN_DSTATE_NUMVAL;
                /* FALLTHRU */
            case CCN_DSTATE_NUMVAL: /* parsing numval */
                c = p[i++];
                if ((c & CCN_TT_HBIT) == CCN_CLOSE) {
                    if (numval > ((~(size_t)0U) >> (7 + CCN_TT_BITS)))
                        state = CCN_DSTATE_ERR_OVERFLOW;
                    numval = (numval << 7) + (c & 127);
                }
                else {
                    numval = (numval << (7-CCN_TT_BITS)) +
                             ((c >> CCN_TT_BITS) & CCN_MAX_TINY);
                    c &= CCN_TT_MASK;
                    switch (c) {
                        case CCN_EXT:
                            if (tagstate == 1) {
                                tagstate = 0;
                                XML(">");
                            }
                            d->nest += 1;
                            d->element_index = d->token_index;
                            state = CCN_DSTATE_NEWTOKEN;
                            break;
                        case CCN_DTAG:
                            if (tagstate == 1) {
                                tagstate = 0;
                                XML(">");
                            }
                            d->nest += 1;
                            d->element_index = d->token_index;
                            XML("<%s");
                            tagstate = 1;
                            state = CCN_DSTATE_NEWTOKEN;
                            break;
                        case CCN_BLOB:
                            if (tagstate == 1) {
                                tagstate = 0;
                                XML(" ccnbencoding=\"base64Binary\">");
                            }
                            state = CCN_DSTATE_BLOB;
                            if (numval == 0)
                                state = CCN_DSTATE_NEWTOKEN;
                            break;
                        case CCN_UDATA:
                            if (tagstate == 1) {
                                tagstate = 0;
                                XML(">");
                            }
                            state = CCN_DSTATE_UDATA;
                            if (numval == 0)
                                state = CCN_DSTATE_NEWTOKEN;
                            break;
                        case CCN_DATTR:
                            if (tagstate != 1) {
                                state = CCN_DSTATE_ERR_ATTR;
                                break;
                            }
                            tagstate = 3;
                            state = CCN_DSTATE_NEWTOKEN;
                            break;
                        case CCN_ATTR:
                            if (tagstate != 1) {
                                state = CCN_DSTATE_ERR_ATTR;
                                break;
                            }
                            numval += 1; /* encoded as length-1 */
                            state = CCN_DSTATE_ATTRNAME;
                            break;
                        case CCN_TAG:
                            if (tagstate == 1) {
                                tagstate = 0;
                                XML(">");
                            }
                            numval += 1; /* encoded as length-1 */
                            d->nest += 1;
                            d->element_index = d->token_index;
                            state = CCN_DSTATE_TAGNAME;
                            break;
                        default:
                            state = CCN_DSTATE_ERR_CODING;
                    }
                    if (pause) {
                        state |= (c << 16);
                        n = i;
                    }
                }
                break;
            case CCN_DSTATE_TAGNAME: /* parsing tag name */
                chunk = n - i;
                if (chunk > numval)
                    chunk = numval;
                if (chunk == 0) {
                    state = CCN_DSTATE_ERR_BUG;
                    break;
                }
                numval -= chunk;
                i += chunk;
                if (numval == 0) {
                    if (d->nest == 0) {
                        state = CCN_DSTATE_ERR_NEST;
                        break;
                    }
                    XML("<%s");
                    tagstate = 1;
                    state = CCN_DSTATE_NEWTOKEN;
                }
                break;
            case CCN_DSTATE_ATTRNAME: /* parsing attribute name */
                chunk = n - i;
                if (chunk > numval)
                    chunk = numval;
                if (chunk == 0) {
                    state = CCN_DSTATE_ERR_BUG;
                    break;
                }
                numval -= chunk;
                i += chunk;
                if (numval == 0) {
                    if (d->nest == 0) {
                        state = CCN_DSTATE_ERR_ATTR;
                        break;
                    }
                    XML(" %s=\"");
                    tagstate = 3;
                    state = CCN_DSTATE_NEWTOKEN;
                }
                break;
            case CCN_DSTATE_UDATA: /* utf-8 data */
            case CCN_DSTATE_BLOB: /* BLOB */
                chunk = n - i;
                if (chunk > numval)
                    chunk = numval;
                if (chunk == 0) {
                    state = CCN_DSTATE_ERR_BUG;
                    break;
                }
                numval -= chunk;
                i += chunk;
                if (numval == 0)
                    state = CCN_DSTATE_NEWTOKEN;
                break;
            default:
                n = i;
        }
    }
    if (state < 0)
        tagstate = pause = 0;
    d->state = state | pause | (tagstate << 8);
    d->numval = numval;
    d->index += i;
    return(i);
}


struct ccn_buf_decoder *
ccn_buf_decoder_start(struct ccn_buf_decoder *d,
                      const unsigned char *buf, size_t size)
{
    memset(&d->decoder, 0, sizeof(d->decoder)); 
    d->decoder.state |= CCN_DSTATE_PAUSE;
    d->buf = buf;
    d->size = size;
    ccn_skeleton_decode(&d->decoder, buf, size);
    return(d);
}

int
ccn_parse_interest(const unsigned char *msg, size_t size,
                   struct ccn_parsed_interest *interest,
                   struct ccn_indexbuf *components)
{
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = ccn_buf_decoder_start(&decoder, msg, size);
    int ncomp = 0;
    if (ccn_buf_match_dtag(d, CCN_DTAG_Interest)) {
        ccn_buf_advance(d);
        interest->offset[CCN_PI_B_Name] = d->decoder.element_index;
        interest->offset[CCN_PI_B_Component0] = d->decoder.index;
        ncomp = ccn_parse_Name(d, components);
        interest->offset[CCN_PI_E_ComponentLast] = d->decoder.token_index - 1;
        interest->offset[CCN_PI_E_Name] = d->decoder.token_index;
        interest->prefix_comps = ncomp;
        interest->offset[CCN_PI_B_LastPrefixComponent] = components->buf[(ncomp > 0) ? (ncomp - 1) : 0];
        interest->offset[CCN_PI_E_LastPrefixComponent] = components->buf[ncomp];
    }
    else
        return (d->decoder.state = -__LINE__);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    if (d->decoder.index != size || !CCN_FINAL_DSTATE(d->decoder.state))
        return (CCN_DSTATE_ERR_CODING);
    return (ncomp);
}


int
ccn_parse_ContentObject(const unsigned char *msg, size_t size,
                        struct ccn_parsed_ContentObject *x,
                        struct ccn_indexbuf *components)
{
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = ccn_buf_decoder_start(&decoder, msg, size);
    int res;
    x->digest_bytes = 0;
    if (ccn_buf_match_dtag(d, CCN_DTAG_ContentObject)) {
        ccn_buf_advance(d);
        res = ccn_parse_Signature(d, x);
        x->offset[CCN_PCO_B_Name] = d->decoder.token_index;
        x->offset[CCN_PCO_B_Component0] = d->decoder.index;
        res = ccn_parse_Name(d, components);
        if (res < 0)
            d->decoder.state = -__LINE__;
        x->name_ncomps = res;
        x->offset[CCN_PCO_E_ComponentLast] = d->decoder.token_index - 1;
        x->offset[CCN_PCO_E_Name] = d->decoder.token_index;
    }
    else
        d->decoder.state = -__LINE__;
    if (d->decoder.index != size || !CCN_FINAL_DSTATE(d->decoder.state))
        return (CCN_DSTATE_ERR_CODING);
    return(0);
}


int
ccn_name_comp_get(const unsigned char *data,
                  const struct ccn_indexbuf *indexbuf,
                  unsigned int i,
                  const unsigned char **comp, size_t *size)
{
    int len;
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d;
    if (indexbuf->n < 2 || i > indexbuf->n - 2) {
	return(-1);
    }
    len = indexbuf->buf[i + 1]-indexbuf->buf[i];
    d = ccn_buf_decoder_start(&decoder, data + indexbuf->buf[i], len);
    if (ccn_buf_match_dtag(d, CCN_DTAG_Component)) {
		ccn_buf_advance(d);
		if (ccn_buf_match_blob(d, comp, size))
			return(0);
		*comp = d->buf + d->decoder.index;
		*size = 0;
		ccn_buf_check_close(d);
		if (d->decoder.state >= 0)
			return(0);
    }
    return(-1);
}


void
ccn_indexbuf_destroy(struct ccn_indexbuf **cbp)
{
    struct ccn_indexbuf *c = *cbp;
    if (c != NULL) {
        if (c->buf != NULL) {
            kfree(c->buf); 
        }
        kfree(c); 
        *cbp = NULL;
    }
}

void
ccn_charbuf_destroy(struct ccn_charbuf **cbp)
{
    struct ccn_charbuf *c = *cbp;
    if (c != NULL) {
        if (c->buf != NULL)
            kfree(c->buf); 
        kfree(c); 
        *cbp = NULL;
    }
}

// PARSE FUNCTION =====================================================

char * parse(char * buff,  int len){
    struct ccn_skeleton_decoder skel_decoder, *sd;
    int packet_type = 0;
    struct ccn_indexbuf *comps;
	const unsigned char *comp;
	struct ccn_parsed_interest interest;
	struct ccn_parsed_interest *pi = &interest;
	struct ccn_parsed_ContentObject co;
	struct ccn_parsed_ContentObject *pco = &co;
	int res;
	unsigned int i, j, not_printable;
	char * ret;
	     
    ret = "ERROR";

    sd = &skel_decoder;
    memset(sd, 0, sizeof(*sd));
    sd->state |= CCN_DSTATE_PAUSE;
    ccn_skeleton_decode(sd, buff, len);
    if (sd->state < 0){
		printk(KERN_WARNING "ERROR: Failure after skeleton decode.");
        return ret;
	}
    if (CCN_GET_TT_FROM_DSTATE(sd->state) == CCN_DTAG)
        packet_type = sd->numval;
    else{
		printk(KERN_WARNING "ERROR: Failure during preliminar parsing.");
		return ret;
	}

    memset(sd, 0, sizeof(*sd));
    ccn_skeleton_decode(sd, buff, len);
	if (!CCN_FINAL_DSTATE(sd->state)) {
		printk(KERN_WARNING "ERROR: DESEGMENT_ONE_MORE_SEGMENT");
		return ret;
	}

    comps = kcalloc(1, sizeof(struct ccn_indexbuf), GFP_ATOMIC);
    ret = kcalloc(50, sizeof(unsigned char), GFP_ATOMIC); 

	switch (packet_type) {
	case CCN_DTAG_ContentObject:
		ccn_parse_ContentObject(buff, sd->index, pco, comps);		
		for (i = 0; i < comps->n; i++) { 
			ccn_name_comp_get(buff, comps, i, &comp, &sd->index);
			not_printable=0;
			if (comp[0]=='\x00')
				break;
			for(j=0; comp[j]!='\x00'; j++)
				if (!isprint(comp[j]))
					not_printable=1;
			//printk(KERN_INFO "Component %d: %s", i, comp);
			strcat(ret, comp);
			if (not_printable==1)
				break;
		}
		break;
	case CCN_DTAG_Interest:
	    res = ccn_parse_interest(buff, sd->index, pi, comps);
	    for (i = 0; i < comps->n; i++) { 
	        ccn_name_comp_get(buff, comps, i, &comp, &sd->index);
			not_printable=0;
			if (comp[0]=='\x00')
				break;
			for(j=0; comp[j]!='\x00'; j++)
				if (!isprint(comp[j]))
					not_printable=1;
			//printk(KERN_INFO "Component %d: %s", i, comp);
			strcat(ret, comp);
			if (not_printable==1)
				break;
	    }
		break;
	}
	
	ccn_indexbuf_destroy(&comps);
	return(ret);
}
