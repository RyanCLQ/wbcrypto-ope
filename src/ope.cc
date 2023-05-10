#include "ope.hh"

using namespace std;
using namespace NTL;

/*
 * A gap is represented by the next integer value _above_ the gap.
 */
static ZZ
domain_gap(const ZZ &ndomain, const ZZ &nrange, const ZZ &rgap, PRNG *prng)//输入定义域大小，值域大小，二分查找值域的中间值，随机数生成函数
{
    return HGD(rgap, ndomain, nrange-ndomain, prng);
}
//把RR的小数部分转换成string
string decimalToString(const NTL::RR& num)
{
    ostringstream oss;
    oss << num;
    string strNum = oss.str();

    // 去除整数部分和小数点，只保留小数部分的字符串
    size_t dotPos = strNum.find('.');
    if (dotPos != string::npos)
    {
        strNum = strNum.substr(dotPos + 1);
    }

    return strNum;
}

//把两个ZZ的部分转换成一个RR
static RR 
IntDecToRR(const ZZ& cint, const ZZ& cdec)
{
    string str_cint = StringFromZZ(cint);
    if(cdec == 0){ 
        return to_RR(cint);
    }
    string str_cdec = StringFromZZ(cdec);

    cout<<cint<<"\n"<<str_cint<<endl;
    cout<<cdec<<"\n"<<str_cdec<<endl;
    // 还原小数点
    str_cint = str_cint + '.' +str_cdec;
    cout<<str_cint<<"  "<<str_cint.c_str();
     cout<<"test"<<endl;
    return to_RR(str_cint.c_str());//todo 可能有错
}

template<class CB>
ope_domain_range
OPE::lazy_sample_sm4(const ZZ &d_lo, const ZZ &d_hi,
                 const ZZ &r_lo, const ZZ &r_hi,
                 CB go_low, blockrng<SM4BS> *prng)
{
    ZZ ndomain = d_hi - d_lo + 1;
    ZZ nrange  = r_hi - r_lo + 1;
    throw_c(nrange >= ndomain);

    if (ndomain == 1)
        return ope_domain_range(d_lo, r_lo, r_hi);

    /*
     * Deterministically reset the PRNG counter, regardless of
     * whether we had to use it for HGD or not in previous round.
     */
    auto v = hmac<sha256>::mac(StringFromZZ(d_lo) + "/" +
                               StringFromZZ(d_hi) + "/" +
                               StringFromZZ(r_lo) + "/" +
                               StringFromZZ(r_hi), key);
    v.resize(SM4BS::blocksize);
    prng->set_ctr(v);

    ZZ rgap = nrange/2;
    ZZ dgap;

    auto ci = dgap_cache.find(r_lo + rgap);
    if (ci == dgap_cache.end()) {
        dgap = domain_gap(ndomain, nrange, nrange / 2, prng);
        dgap_cache[r_lo + rgap] = dgap;
    } else {
        dgap = ci->second;
    }

    if (go_low(d_lo + dgap, r_lo + rgap))
        return lazy_sample_sm4(d_lo, d_lo + dgap - 1, r_lo, r_lo + rgap - 1, go_low, prng);
    else
        return lazy_sample_sm4(d_lo + dgap, d_hi, r_lo + rgap, r_hi, go_low, prng);
}


template<class CB>
ope_domain_range
OPE::lazy_sample_wbsm4(const ZZ &d_lo, const ZZ &d_hi,
                 const ZZ &r_lo, const ZZ &r_hi,
                 CB go_low, blockrng<WBSM4SE> *prng)
{
    ZZ ndomain = d_hi - d_lo + 1;
    ZZ nrange  = r_hi - r_lo + 1;
    throw_c(nrange >= ndomain);

    if (ndomain == 1)
        return ope_domain_range(d_lo, r_lo, r_hi);

    /*
     * Deterministically reset the PRNG counter, regardless of
     * whether we had to use it for HGD or not in previous round.
     */
    auto v = hmac<sha256>::mac(StringFromZZ(d_lo) + "/" +
                               StringFromZZ(d_hi) + "/" +
                               StringFromZZ(r_lo) + "/" +
                               StringFromZZ(r_hi), key);
    v.resize(WBSM4SE::blocksize);
    prng->set_ctr(v);

    ZZ rgap = nrange/2;
    ZZ dgap;

    auto ci = dgap_cache.find(r_lo + rgap);
    if (ci == dgap_cache.end()) {
        dgap = domain_gap(ndomain, nrange, nrange / 2, prng);
        dgap_cache[r_lo + rgap] = dgap;
    } else {
        dgap = ci->second;
    }

    if (go_low(d_lo + dgap, r_lo + rgap))
        return lazy_sample_wbsm4(d_lo, d_lo + dgap - 1, r_lo, r_lo + rgap - 1, go_low, prng);
    else
        return lazy_sample_wbsm4(d_lo + dgap, d_hi, r_lo + rgap, r_hi, go_low, prng);
}

template<class CB>
ope_domain_range
OPE::search_sm4(CB go_low)
{
    blockrng<SM4BS> r(block_key1);

    return lazy_sample_sm4(to_ZZ(0), to_ZZ(1) << pbits,
                       to_ZZ(0), to_ZZ(1) << cbits,
                       go_low, &r);
}

template<class CB>
ope_domain_range
OPE::search_wbsm4(CB go_low)
{
    blockrng<WBSM4SE> r(block_key2);

    return lazy_sample_wbsm4(to_ZZ(0), to_ZZ(1) << pbits,
                       to_ZZ(0), to_ZZ(1) << cbits,
                       go_low, &r);
}


ZZ
OPE::encrypt_sm4(int ptext){
	ZZ plaintext_ZZ = to_ZZ(ptext);
	return encrypt_sm4(plaintext_ZZ);
}

ZZ
OPE::encrypt_wbsm4(int ptext){
	ZZ plaintext_ZZ = to_ZZ(ptext);
	return encrypt_wbsm4(plaintext_ZZ);
}

RR
OPE::encrypt_sm4(float ptext){
	RR plaintext_RR = to_RR(ptext);
	return encrypt_sm4(plaintext_RR);
}

RR
OPE::encrypt_wbsm4(float ptext){
	RR plaintext_RR = to_RR(ptext);
	return encrypt_wbsm4(plaintext_RR);
}

ZZ
OPE::encrypt_sm4(const ZZ &ptext)
{
    ope_domain_range dr =
        search_sm4([&ptext](const ZZ &d, const ZZ &) { return ptext < d; });

    auto v = sha256::hash(StringFromZZ(ptext));
    v.resize(16);

    blockrng<SM4BS> rand(block_key1);
    rand.set_ctr(v);

    ZZ nrange = dr.r_hi - dr.r_lo + 1;
    return dr.r_lo + rand.rand_zz_mod(nrange);
}

ZZ
OPE::encrypt_wbsm4(const ZZ &ptext)
{
    ope_domain_range dr =
        search_wbsm4([&ptext](const ZZ &d, const ZZ &) { return ptext < d; });//传入比较大小的函数，输入明文和d去比较，占位符是留给解密的r的，没有用到

    auto v = sha256::hash(StringFromZZ(ptext));
    v.resize(16);

    blockrng<WBSM4SE> rand(block_key2);
    rand.set_ctr(v);

    ZZ nrange = dr.r_hi - dr.r_lo + 1;
    return dr.r_lo + rand.rand_zz_mod(nrange);
}

RR
OPE::encrypt_sm4(const RR &ptext)
{
    ZZ pint = NTL::TruncToZZ(ptext);//整数部分
    string decimal = decimalToString(ptext); 
    ZZ pdec = ZZFromString(decimal);//小数部分

    ope_domain_range dint =
        search_sm4([&pint](const ZZ &d, const ZZ &) { return pint < d; });
    ope_domain_range ddec =
        search_sm4([&pdec](const ZZ &d, const ZZ &) { return pdec < d; });

    ostringstream oss;
    oss << ptext;
    string str_ptext = oss.str();
    
    auto v = sha256::hash(str_ptext); 
    v.resize(16);
    
    blockrng<SM4BS> rand(block_key1);
    rand.set_ctr(v);

    ZZ intrange = dint.r_hi - dint.r_lo + 1;
    ZZ decrange = ddec.r_hi - ddec.r_lo + 1;
    ZZ cint = dint.r_lo + rand.rand_zz_mod(intrange);
    ZZ cdec = ddec.r_lo + rand.rand_zz_mod(decrange);
   
    return IntDecToRR(cint,cdec);
}

RR
OPE::encrypt_wbsm4(const RR &ptext)
{
    ZZ pint = NTL::TruncToZZ(ptext);//整数部分
    string decimal = decimalToString(ptext); 
    ZZ pdec = ZZFromString(decimal);//小数部分

    ope_domain_range dint =
        search_wbsm4([&pint](const ZZ &d, const ZZ &) { return pint < d; });
    ope_domain_range ddec =
        search_wbsm4([&pdec](const ZZ &d, const ZZ &) { return pdec < d; });

    ostringstream oss;
    oss << ptext;
    string str_ptext = oss.str();
    
    auto v = sha256::hash(str_ptext); 
    v.resize(16);

    blockrng<WBSM4SE> rand(block_key2);
    rand.set_ctr(v);

    ZZ intrange = dint.r_hi - dint.r_lo + 1;
    ZZ decrange = ddec.r_hi - ddec.r_lo + 1;
    ZZ cint = dint.r_lo + rand.rand_zz_mod(intrange);
    ZZ cdec = ddec.r_lo + rand.rand_zz_mod(decrange);

    return IntDecToRR(cint,cdec);
}

ZZ
OPE::decrypt_sm4(const ZZ &ctext)
{
    ope_domain_range dr =
        search_sm4([&ctext](const ZZ &, const ZZ &r) { return ctext < r; });
    return dr.d;
}

ZZ
OPE::decrypt_wbsm4(const ZZ &ctext)
{
    ope_domain_range dr =
        search_wbsm4([&ctext](const ZZ &, const ZZ &r) { return ctext < r; });
    return dr.d;
}

RR
OPE::decrypt_sm4(const RR &ctext)
{
    ZZ cint = NTL::TruncToZZ(ctext);//整数部分
    string decimal = decimalToString(ctext); 
    ZZ cdec = ZZFromString(decimal);//小数部分
    ope_domain_range dint =
        search_sm4([&cint](const ZZ &, const ZZ &r) { return cint < r; });
    
    ope_domain_range ddec =
        search_sm4([&cdec](const ZZ &, const ZZ &r) { return cdec < r; });    
         
    cout<<"输出的解密RR"<<IntDecToRR(dint.d,ddec.d)<<endl;     
    return IntDecToRR(dint.d,ddec.d);
}

RR
OPE::decrypt_wbsm4(const RR &ctext)
{
    ZZ cint = NTL::TruncToZZ(ctext);//整数部分
    string decimal = decimalToString(ctext); 
    ZZ cdec = ZZFromString(decimal);//小数部分
    ope_domain_range dint =
        search_wbsm4([&cint](const ZZ &, const ZZ &r) { return cint < r; });
    
    ope_domain_range ddec =
        search_wbsm4([&cdec](const ZZ &, const ZZ &r) { return cdec < r; });    
         
    cout<<"输出的解密RR"<<IntDecToRR(dint.d,ddec.d)<<endl;     
    return IntDecToRR(dint.d,ddec.d);
}

