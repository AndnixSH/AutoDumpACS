char * findDosHeader(char * buffer, int length, int *out_length) {
    char * pe = NULL;
    for (int i = 0; i < length - 0x200; i++) {
        WORD * p = (WORD *)(buffer + i);
        if (*p != IMAGE_DOS_SIGNATURE) {
            continue;
        }
        IMAGE_NT_HEADERS * ntheader = (IMAGE_NT_HEADERS *)(buffer + 0x80 + i);
        if (ntheader->Signature != IMAGE_NT_SIGNATURE){
            continue;
        }
        IMAGE_FILE_HEADER * fileheader = &ntheader->FileHeader;
        if (!(fileheader->Characteristics & IMAGE_FILE_DLL)){
            continue;
        }
        IMAGE_SECTION_HEADER * section = IMAGE_FIRST_SECTION(ntheader);
        int size = 0;
        for (int j = 0; j < fileheader->NumberOfSections; j++) {
            if ((section + j)->SizeOfRawData + (section + j)->PointerToRawData > size) {
                size = (section + j)->SizeOfRawData + (section + j)->PointerToRawData;
            }
        }
        *out_length = size;
        return (buffer + i);
    }
    return NULL;
}
 
void find(const char * fileName) {
    FILE *fp = NULL;
    fopen_s(&fp, fileName, "rb");
    if (fp == NULL) {
        return;
    }
    fseek(fp, 0L, SEEK_END);
    int length = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
 
    char * pFileBuffer = new char[length];
    fread_s(pFileBuffer, length, 1, length, fp);
    char* ppe = pFileBuffer;
    int image_length = 0;
    int buffer_length = length;
    while (true)
    {
        char f[512];
        buffer_length -= image_length;
        ppe = findDosHeader(ppe + image_length, length - (ppe - pFileBuffer) - image_length, &image_length);
        if (ppe != NULL) {
            sprintf_s(f, "%s.%x-%x.dll", fileName, ppe, image_length);
            FILE* outfp = 0;
            fopen_s(&outfp, f, "wb+");
            fwrite(ppe, image_length, 1, outfp);
            fclose(outfp);
            printf("%x %x\n", ppe, image_length);
        }
        else{
            break;
        }
    }
     
    delete[] pFileBuffer;
    fclose(fp);
}
