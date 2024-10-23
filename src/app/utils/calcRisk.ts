interface VirustotalStatsForDomain {
    harmless: number,
    malicious: number,
    suspicious: number,
    undetected: number,
    timeout: number
}

export function calcRisk(virsusTotalStatsForDomain: VirustotalStatsForDomain) {
    const { malicious, suspicious } = virsusTotalStatsForDomain;

    if(malicious > 0) {
        return "High Risk"
    }

    if (suspicious > 0) {
        return "Moderate Risk"
    }

    return "Low Risk"
}
