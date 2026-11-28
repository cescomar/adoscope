# Used by Test-AdoScopeLab.ps1. The lab never runs its pipelines or commits again, so checks
# that depend on elapsed time (HYG001 after 90 days, HYG002 after 180) would start reporting
# lab resources on their own and make the nightly check fail without any API change.
# AGT001 compares projects of different trust groups; a one-project lab has nothing to compare.
@{
    Checks = @{
        Disabled = @('HYG001', 'HYG002', 'AGT001')
    }
}
