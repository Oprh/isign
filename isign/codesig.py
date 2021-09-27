from abc import ABCMeta
import construct
import hashlib
import logging
import macho_cs
import makesig

import ents
import plistlib

import traceback
import utils

log = logging.getLogger(__name__)


# See the documentation for an explanation of how
# CodeDirectory slots work.
class CodeDirectorySlot(object):
    __metaclass__ = ABCMeta
    offset = None

    def __init__(self, codesig):
        self.codesig = codesig

    def get_hash(self, hash_algorithm):
        if hash_algorithm == "sha1":
            return hashlib.sha1(self.get_contents()).digest()
        elif hash_algorithm == "sha256":
            return hashlib.sha256(self.get_contents()).digest()

class DerEntitlementsSlot(CodeDirectorySlot):
    offset = -7

    def get_contents(self):
        blobs = self.codesig.get_blobs('CSMAGIC_DER_ENTITLEMENT', min_expected=1, max_expected=1)
        return self.codesig.get_blob_data(blobs[0])
    
  #  def get_hash(self, hash_algorithm):
   #     return '\x00' * 20

class EntitlementsSlot(CodeDirectorySlot):
    offset = -5

    def get_contents(self):
        blobs = self.codesig.get_blobs('CSMAGIC_ENTITLEMENT', min_expected=1, max_expected=1)
        return self.codesig.get_blob_data(blobs[0])


class ApplicationSlot(CodeDirectorySlot):
    offset = -4

    def get_hash(self, hash_algorithm):
        return '\x00' * (20 if hash_algorithm == 'sha1' else 32)


class ResourceDirSlot(CodeDirectorySlot):
    offset = -3

    def __init__(self, seal_path):
        self.seal_path = seal_path

    def get_contents(self):
        return open(self.seal_path, "rb").read()


class RequirementsSlot(CodeDirectorySlot):
    offset = -2

    def get_contents(self):
        blobs = self.codesig.get_blobs('CSMAGIC_REQUIREMENTS', min_expected=1, max_expected=1)
        return self.codesig.get_blob_data(blobs[0])


class InfoSlot(CodeDirectorySlot):
    offset = -1

    def __init__(self, info_path):
        self.info_path = info_path

    def get_contents(self):
        return open(self.info_path, "rb").read()


# Represents a code signature object, aka the LC_CODE_SIGNATURE,
# within the Signable
class Codesig(object):
    """ wrapper around construct for code signature """
    def __init__(self, signable, data):
        self.signable = signable
        self.construct = macho_cs.Blob.parse(data)
        self.is_sha256 = len(self.construct.data.BlobIndex) >= 6

    def is_sha256_signature(self):
        return self.is_sha256

    def build_data(self):
        return macho_cs.Blob.build(self.construct)

    def get_blobs(self, magic, min_expected=None, max_expected=None):
        """ get the blobs corresponding to the magic value from the blob index """
        blobs = []
        for index in self.construct.data.BlobIndex:
            if index.blob.magic == magic:
                blobs.append(index.blob)

        if min_expected != None and len(blobs) < min_expected:
            raise KeyError("""The number of slots in blob index for magic '{}' was less than
                the minimum expected ({})""".format(magic, min_expected))

        if max_expected != None and len(blobs) > max_expected:
            raise KeyError("""The number of slots in blob index for magic '{}' was more than
                the maximum expected ({})""".format(magic, max_expected))


        return blobs

    def get_blob_data(self, blob):
        """ convenience method, if we just want the data """
        return macho_cs.Blob_.build(blob)
        
        
    def set_binary_entitlements(self, entitlements_path):
        try:
            binary_ent_blobs = self.get_blobs('CSMAGIC_ENTITLEMENT_BINARY', min_expected=0, max_expected=1)
        except KeyError:
            # log.debug("no entitlements found")
            pass
        else:
            if len(binary_ent_blobs) > 0:
                binaryEnt = binary_ent_blobs[0]
               # print('{} debug with value {}'.format(type(binaryEnt.data.data), binaryEnt.data.data))
             #   ent, rest = decoder.decode(binaryEnt.data.data, ents.Ents())
                ent = binaryEnt.data.data
                xml = plistlib.readPlistFromString(open(entitlements_path, "rb").read())
                for field in ent:
                    aval = field['val'].getComponent()
                    akey = field['key']
                    xval = xml.get(akey)
                    log.debug("Original key %s val %s", akey, aval)
                    if xval is not None:
                        log.debug("New val %s class %s", xval, type(xval))
                        if isinstance(aval, pyasn1.type.char.UTF8String):
                            newVal = ''.join(xval) if isinstance(xval, list) else xval
                            if akey == 'application-identifier' and self.signable.suffix is not None:
                                newVal = newVal + self.signable.suffix
                            field['val'].setComponentByType(field['val'].effectiveTagSet, value=pyasn1.type.char.UTF8String(newVal))
                            log.debug("Replaced with %s", field['val'])
                        elif isinstance(aval, ents.ListValues):
                            for i, xel in enumerate(xval):
                                aval.setComponentByPosition(i, value=pyasn1.type.char.UTF8String(xel))
                bts = encode(ent)
                binaryEnt.bytes = bts
                binaryEnt.length = len(binaryEnt.bytes) + 8
    

    def set_entitlements(self, entitlements_path):
        # log.debug("entitlements:")
        try:
            entitlements_blobs = self.get_blobs('CSMAGIC_ENTITLEMENT', min_expected=1, max_expected=1)
            entitlements = entitlements_blobs[0]
            # log.debug("found entitlements slot in the image")
        except KeyError:
            # log.debug("no entitlements found")
            pass
        else:
            # make entitlements data if slot was found
            # libraries do not have entitlements data
            # so this is actually a difference between libs and apps
            # entitlements_data = macho_cs.Blob_.build(entitlements)
            # log.debug(hashlib.sha1(entitlements_data).hexdigest())

            log.debug("using entitlements at path: {}".format(entitlements_path))
            entitlements.bytes = open(entitlements_path, "rb").read()
            entitlements.length = len(entitlements.bytes) + 8
    
    def set_bundleID(self, newId, req_blob_0):
        prev = [req_blob_0.data.expr]
        while prev:
            expr = prev.pop()
            log.debug('Expr %s', expr)
            op = expr.op
            log.debug('op %s', op)
            if op == 'opAnd' or op == 'opOr':
                prev.append(expr.data[0])
                prev.append(expr.data[1])
            elif op == 'opIdent':
                log.debug('elems %s class %s', expr, type(expr))
                expr.data.data = newId
                expr.data.length = len(expr.data.data)
                
    
    def set_requirements(self, signer):
        # log.debug("requirements:")
        requirements_blobs = self.get_blobs('CSMAGIC_REQUIREMENTS', min_expected=1, max_expected=1)
        requirements = requirements_blobs[0]
        # requirements_data = macho_cs.Blob_.build(requirements)
        # log.debug(hashlib.sha1(requirements_data).hexdigest())
        req_blob_0 = requirements.data.BlobIndex[0].blob
        req_blob_0_original_length = req_blob_0.length
        signer_cn = signer.get_common_name()
        
        try:
            cn = req_blob_0.data.expr.data[1].data[1].data[0].data[2].Data
        except Exception:
            log.debug("no signer CN rule found in requirements. Redi")
            log.debug(requirements)
            # here we insert an entire new expr since it is too hard to add leaf
            expr = makesig.make_expr(
                'And',
                ('Ident', self.signable.bundleId),
                ('AppleGenericAnchor',),
                ('CertField', 'leafCert', 'subject.CN', ['matchEqual', signer_cn]),
                ('CertGeneric', 1, '*\x86H\x86\xf7cd\x06\x02\x01', ['matchExists']))
            des_req = construct.Container(kind=1, expr=expr)
            des_req_data = macho_cs.Requirement.build(des_req)
            requirements.data.BlobIndex[0].blob=construct.Container(magic='CSMAGIC_REQUIREMENT',
                                                            length=len(des_req_data) + 8,
                                                            data=des_req,
                                                            bytes=des_req_data)
            log.debug('New requirements %s', requirements)
        else:
            # if we could find a signer CN rule, make requirements.
            log.debug('Req blob %s', req_blob_0)
            self.set_bundleID(self.signable.bundleId, req_blob_0)
            # first, replace old signer CN with our own
            cn.data = signer_cn
            cn.length = len(cn.data)

        # this is for convenience, a reference to the first blob
        # structure within requirements, which contains the data
        # we are going to change




        # req_blob_0 contains that CN, so rebuild it, and get what
        # the length is now
        req_blob_0.bytes = macho_cs.Requirement.build(req_blob_0.data)
        req_blob_0.length = len(req_blob_0.bytes) + 8

        # fix offsets of later blobs in requirements
        offset_delta = req_blob_0.length - req_blob_0_original_length
        for bi in requirements.data.BlobIndex[1:]:
            bi.offset += offset_delta

        # rebuild requirements, and set length for whole thing
        requirements.bytes = macho_cs.Entitlements.build(requirements.data)
        requirements.length = len(requirements.bytes) + 8

        # then rebuild the whole data, but just to show the digest...?
        # requirements_data = macho_cs.Blob_.build(requirements)
        # log.debug(hashlib.sha1(requirements_data).hexdigest())

    def get_codedirectory_hash_index(self, slot, code_directory):
        """ The slots have negative offsets, because they start from the 'top'.
            So to get the actual index, we add it to the length of the
            slots. """
        return slot.offset + code_directory.data.nSpecialSlots

    def has_codedirectory_slot(self, slot, code_directory):
        """ Some dylibs have all 5 slots, even though technically they only need
            the first 2. If this dylib only has 2 slots, some of the calculated
            indices for slots will be negative. This means we don't do
            those slots when resigning (for dylibs, they don't add any
            security anyway) """
        return self.get_codedirectory_hash_index(slot, code_directory) >= 0

    def fill_codedirectory_slot(self, slot, code_directory, hash_algorithm):
        if self.signable.should_fill_slot(self, slot):
            index = self.get_codedirectory_hash_index(slot, code_directory)
            log.debug('Filling slot %s', type(slot).__name__)
            code_directory.data.hashes[index] = slot.get_hash(hash_algorithm)

    def set_codedirectories(self, seal_path, info_path, signer):
        cd = self.get_blobs('CSMAGIC_CODEDIRECTORY', min_expected=1, max_expected=2)
        changed_bundle_id = self.signable.get_changed_bundle_id()
        
        hash_size_sha_mapping = {32: 'sha256', 20 : 'sha1'}

        for i, code_directory in enumerate(cd):
            # TODO: Is there a better way to figure out which hashing algorithm we should use?
            hash_algorithm = hash_size_sha_mapping.get(code_directory.data.hashSize)
            log.debug('Hash algorithm %s', hash_algorithm)

            if self.has_codedirectory_slot(EntitlementsSlot, code_directory):
                self.fill_codedirectory_slot(EntitlementsSlot(self), code_directory, hash_algorithm)

            if self.has_codedirectory_slot(ResourceDirSlot, code_directory):
                self.fill_codedirectory_slot(ResourceDirSlot(seal_path), code_directory, hash_algorithm)

            if self.has_codedirectory_slot(RequirementsSlot, code_directory):
                self.fill_codedirectory_slot(RequirementsSlot(self), code_directory, hash_algorithm)

            if self.has_codedirectory_slot(ApplicationSlot, code_directory):
                self.fill_codedirectory_slot(ApplicationSlot(self), code_directory, hash_algorithm)

            if self.has_codedirectory_slot(InfoSlot, code_directory):
                self.fill_codedirectory_slot(InfoSlot(info_path), code_directory, hash_algorithm)
                
            if self.has_codedirectory_slot(DerEntitlementsSlot, code_directory):
                self.fill_codedirectory_slot(DerEntitlementsSlot(self), code_directory, hash_algorithm)

            code_directory.data.teamID = signer.team_id

            if changed_bundle_id:
                offset_change = len(changed_bundle_id) - len(code_directory.data.ident)
                code_directory.data.ident = changed_bundle_id
                code_directory.data.hashOffset += offset_change
                if code_directory.data.teamIDOffset == None:
                    code_directory.data.teamIDOffset = offset_change
                else:
                    code_directory.data.teamIDOffset += offset_change
                code_directory.length += offset_change
            
            code_directory.bytes = macho_cs.CodeDirectory.build(code_directory.data)
            # cd_data = macho_cs.Blob_.build(cd)
            # log.debug(len(cd_data))
            # open("cdrip", "wb").write(cd_data)
            # log.debug("CDHash:" + hashlib.sha1(cd_data).hexdigest())

    def set_signature(self, signer):
        # TODO how do we even know this blobwrapper contains the signature?
        # seems like this is a coincidence of the structure, where
        # it's the only blobwrapper at that level...
        # log.debug("sig:")
        blob_wrappers = self.get_blobs('CSMAGIC_BLOBWRAPPER', min_expected=1, max_expected=1)
        sigwrapper = blob_wrappers[0]

        # oldsig = sigwrapper.bytes.value
        # signer._log_parsed_asn1(sigwrapper.data.data.value)
        # open("sigrip.der", "wb").write(sigwrapper.data.data.value)

        code_directories = self.get_blobs('CSMAGIC_CODEDIRECTORY', min_expected=1, max_expected=2)
        cd_data = self.get_blob_data(code_directories[0])
        sig = signer.sign(cd_data, 'sha1')
        # log.debug("sig len: {0}".format(len(sig)))
        # log.debug("old sig len: {0}".format(len(oldsig)))
        # open("my_sigrip.der", "wb").write(sig)
        sigwrapper.data = construct.Container(data=sig)
        # signer._log_parsed_asn1(sig)
        # sigwrapper.data = construct.Container(data="hahaha")
        sigwrapper.length = len(sigwrapper.data.data) + 8
        sigwrapper.bytes = sigwrapper.data.data
        # log.debug(len(sigwrapper.bytes))

    def update_offsets(self):
        # update section offsets, to account for any length changes
   #     elBin = next((blob for blob in self.construct.data.BlobIndex if blob.type == 7), None)
   #     if elBin:
   #         self.construct.data.BlobIndex = [blob for blob in self.construct.data.BlobIndex if blob.type != 7]
   #         self.construct.data.count = self.construct.data.count - 1
        offset = self.construct.data.BlobIndex[0].offset
        for blob in self.construct.data.BlobIndex:
            blob.offset = offset
            blob_data = macho_cs.Blob.build(blob.blob)
            offset += len(blob_data)

        superblob = macho_cs.SuperBlob.build(self.construct.data)
        self.construct.length = len(superblob) + 8
        self.construct.bytes = superblob
        
    def can_resign(self):
        codedirs = self.get_blobs('CSMAGIC_CODEDIRECTORY', min_expected=1, max_expected=2)
        code_directory = codedirs[0]
        if code_directory.data.version >= 0x20500 :
            return False
        return True

    def resign(self, bundle, signer,info_path,  seal_path):
        """ Do the actual signing. Create the structre and then update all the
            byte offsets """
        codedirs = self.get_blobs('CSMAGIC_CODEDIRECTORY', min_expected=1, max_expected=2)

        # TODO - the way entitlements are handled is a code smell
        # 1 - We're doing a hasattr to detect whether it's a top-level app. isinstance(App, bundle) ?
        # 2 - unlike the seal_path and info_path, the entitlements_path is not functional. Apps are verified
        #     based on the entitlements encoded into the code signature and slots and MAYBE the pprof.
        # Possible refactor - make entitlements data part of Signer rather than Bundle?
        if hasattr(bundle, 'entitlements_path') and bundle.entitlements_path is not None:
            self.set_entitlements(bundle.entitlements_path)
            self.set_binary_entitlements(bundle.entitlements_path)
        self.set_requirements(signer)
        # See docs/codedirectory.rst for some notes on optional hashes
        self.set_codedirectories(seal_path, info_path, signer)
        self.set_signature(signer)
        self.update_offsets()

    # TODO make this optional, in case we want to check hashes or something
    # log.debug(hashes)
    # cd = codesig_cons.data.BlobIndex[0].blob.data
    # end_offset = arch_macho.macho_start + cd.codeLimit
    # start_offset = ((end_offset + 0xfff) & ~0xfff) - (cd.nCodeSlots * 0x1000)

    # for i in xrange(cd.nSpecialSlots):
    #    expected = cd.hashes[i]
    #    log.debug("special exp=%s" % expected.encode('hex'))

    # for i in xrange(cd.nCodeSlots):
    #     expected = cd.hashes[cd.nSpecialSlots + i]
    #     f.seek(start_offset + 0x1000 * i)
    #     actual_data = f.read(min(0x1000, end_offset - f.tell()))
    #     actual = hashlib.sha1(actual_data).digest()
    #     log.debug('[%s] exp=%s act=%s' % ()
    #         ('bad', 'ok ')[expected == actual],
    #         expected.encode('hex'),
    #         actual.encode('hex')
    #     )
