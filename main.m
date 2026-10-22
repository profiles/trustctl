#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <unistd.h>

typedef struct __SecTrustStore *SecTrustStoreRef;
extern SecTrustStoreRef SecTrustStoreForDomain(int domain);
extern OSStatus SecTrustStoreSetTrustSettings(SecTrustStoreRef store, SecCertificateRef cert, CFTypeRef trustSettings);
extern OSStatus SecTrustStoreRemoveCertificate(SecTrustStoreRef store, SecCertificateRef cert);
extern OSStatus SecTrustStoreCopyAll(SecTrustStoreRef store, CFArrayRef *allOut);

static const int kDefaultDomain = 2;

static NSData *loadCertificateData(NSString *path) {
    NSData *raw = [path isEqualToString:@"-"]
        ? [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile]
        : [NSData dataWithContentsOfFile:path];
    if (raw.length == 0) return nil;
    if (raw.length > 11 && memcmp(raw.bytes, "-----BEGIN", 10) == 0) {
        NSString *text = [[NSString alloc] initWithData:raw encoding:NSUTF8StringEncoding];
        if (!text) return nil;
        NSMutableString *body = [NSMutableString string];
        for (NSString *line in [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
            if (![line hasPrefix:@"-"]) [body appendString:line];
        }
        return [[NSData alloc] initWithBase64EncodedString:body options:0];
    }
    return raw;
}

static SecCertificateRef loadCert(NSString *path) {
    NSData *data = loadCertificateData(path);
    if (!data) {
        fprintf(stderr, "[-] cannot read %s\n", path.UTF8String);
        return nil;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
    if (!cert) {
        fprintf(stderr, "[-] not a valid certificate (DER/PEM): %s\n", path.UTF8String);
        return nil;
    }
    return cert;
}

static void describe(SecCertificateRef cert) {
    CFStringRef s = SecCertificateCopySubjectSummary(cert);
    if (!s) { printf("[+] cert: (no summary)\n"); return; }
    printf("[+] cert: %s\n", [(__bridge_transfer NSString *)s UTF8String]);
}

static int doAdd(NSString *path, int domain) {
    SecCertificateRef cert = loadCert(path);
    if (!cert) return 1;
    describe(cert);
    SecTrustStoreRef store = SecTrustStoreForDomain(domain);
    if (!store) { fprintf(stderr, "[-] SecTrustStoreForDomain(%d) returned NULL\n", domain); return 1; }
    OSStatus st = SecTrustStoreSetTrustSettings(store, cert, NULL);
    printf("[+] add: %d\n", (int)st);
    CFRelease(cert);
    return st == errSecSuccess ? 0 : 1;
}

static int doDel(NSString *path, int domain) {
    SecCertificateRef cert = loadCert(path);
    if (!cert) return 1;
    describe(cert);
    SecTrustStoreRef store = SecTrustStoreForDomain(domain);
    if (!store) { fprintf(stderr, "[-] SecTrustStoreForDomain(%d) returned NULL\n", domain); return 1; }
    OSStatus st = SecTrustStoreRemoveCertificate(store, cert);
    printf("[+] del: %d\n", (int)st);
    CFRelease(cert);
    return st == errSecSuccess ? 0 : 1;
}

static int doEval(NSString *path) {
    SecCertificateRef cert = loadCert(path);
    if (!cert) return 1;
    describe(cert);
    SecTrustRef trust = NULL;
    OSStatus st = SecTrustCreateWithCertificates(cert, SecPolicyCreateBasicX509(), &trust);
    if (st != errSecSuccess) {
        fprintf(stderr, "[-] SecTrustCreateWithCertificates: %d\n", (int)st);
        return 1;
    }
    CFErrorRef err = NULL;
    BOOL trusted = SecTrustEvaluateWithError(trust, &err);
    printf("[+] eval: %s\n", trusted ? "TRUSTED" : "NOT TRUSTED");
    if (err) {
        NSString *d = (__bridge_transfer NSString *)CFErrorCopyDescription(err);
        printf("    %s\n", d.UTF8String);
    }
    CFRelease(trust);
    CFRelease(cert);
    return trusted ? 0 : 2;
}

static int doList(int domain) {
    SecTrustStoreRef store = SecTrustStoreForDomain(domain);
    if (!store) { fprintf(stderr, "[-] SecTrustStoreForDomain(%d) returned NULL\n", domain); return 1; }
    CFArrayRef allRef = NULL;
    OSStatus st = SecTrustStoreCopyAll(store, &allRef);
    if (st != errSecSuccess || !allRef) {
        printf("[+] list: (empty, %d)\n", (int)st);
        return st == errSecSuccess ? 0 : 1;
    }
    NSArray *all = (__bridge_transfer NSArray *)allRef;
    printf("[+] list: %ld entries (domain %d)\n", (long)all.count, domain);
    NSUInteger idx = 0;
    for (NSArray *entry in all) {
        idx++;
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)entry[0]);
        if (!cert) continue;
        CFStringRef s = SecCertificateCopySubjectSummary(cert);
        NSArray *settings = entry.count > 1 ? entry[1] : nil;
        printf("    %lu. %s%s\n", (unsigned long)idx,
               s ? [(__bridge_transfer NSString *)s UTF8String] : "(no summary)",
               settings.count == 0 ? " (full trust)" : "");
        CFRelease(cert);
    }
    return 0;
}

static void usage(const char *prog) {
    printf("usage: %s -a <cert.der|pem|-> [-D domain]   trust certificate as root CA\n", prog);
    printf("       %s -d <cert.der|pem|-> [-D domain]   remove certificate from trust store\n", prog);
    printf("       %s -e <cert.der|pem|->               evaluate system trust\n", prog);
    printf("       %s -l [-D domain]                list certificates in trust store\n", prog);
    printf("\n");
    printf("  stdin is the most reliable input:  cat ca.der | %s -a -\n", prog);
    printf("  roothide note: paths differ per process context. The ssh shell's\n");
    printf("  /tmp is inside the jail, so a file copied there is NOT visible here.\n");
    printf("  Copy via the real filesystem instead:\n");
    printf("      cp ca.der /rootfs/tmp/ca.der   (from ssh shell)\n");
    printf("      %s -a /tmp/ca.der    (this tool sees the real /tmp)\n", prog);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        int domain = kDefaultDomain;
        NSString *certPath = nil;
        int action = 0;
        int opt;
        while ((opt = getopt(argc, argv, "a:d:e:lD:h")) != -1) {
            switch (opt) {
                case 'a':
                case 'd':
                case 'e':
                    action = opt;
                    certPath = @(optarg);
                    break;
                case 'l': action = 'l'; break;
                case 'D': domain = atoi(optarg); break;
                case 'h': usage(argv[0]); return 0;
                default:  usage(argv[0]); return 2;
            }
        }
        switch (action) {
            case 'a': return doAdd(certPath, domain);
            case 'd': return doDel(certPath, domain);
            case 'e': return doEval(certPath);
            case 'l': return doList(domain);
            default:  usage(argv[0]); return 2;
        }
    }
}
