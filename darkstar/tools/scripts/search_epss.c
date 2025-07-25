#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

// Function to search for a CVE and return its EPSS score
void search_cve(const char *filename, const char *target_cve) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return;
    }

    char line[MAX_LINE_LENGTH];
    int found = 0;

    // Skip the first two lines (header and model info)
    fgets(line, MAX_LINE_LENGTH, file); // Skip model version line
    fgets(line, MAX_LINE_LENGTH, file); // Skip header line

    while (fgets(line, MAX_LINE_LENGTH, file)) {
        char *cve = strtok(line, ",");
        char *epss = strtok(NULL, ",");
        // Percentile can be extracted if needed with strtok(NULL, ",").

        if (cve && epss && strcmp(cve, target_cve) == 0) {
            printf("%s\n", epss);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("CVE %s not found in the file.\n", target_cve);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <cve_number>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *cve_input = argv[2];

    search_cve(filename, cve_input);

    return 0;
}
