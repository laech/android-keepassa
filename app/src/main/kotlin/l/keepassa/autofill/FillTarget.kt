package l.keepassa.autofill

data class FillTarget(
    val packageId: String?,
    val webDomain: String?,
    val usernameField: Structure.View?,
    val passwordField: Structure.View?
) {

    fun tryUpdate(window: Structure.Window): FillTarget =
        window.textFields().fold(
            tryUpdatePackageId(window),
            FillTarget::tryUpdate
        )

    private fun tryUpdatePackageId(window: Structure.Window) =
        if (packageId != null) {
            this
        } else {
            when (val packageId = window.extractPackageIdFromTitle()) {
                null -> this
                else -> copy(packageId = packageId)
            }
        }

    private fun tryUpdate(view: Structure.View): FillTarget =
        tryUpdatePackageId(view).tryUpdateFields(view)

    private fun tryUpdatePackageId(view: Structure.View) =
        when (view.packageId) {
            null -> this
            else -> copy(packageId = view.packageId)
        }

    private fun tryUpdateFields(view: Structure.View) =
        when {
            view.isUsernameField() -> copy(usernameField = view)
            view.isPasswordField() -> copy(passwordField = view)
            else -> this
        }
}

val emptyFillTarget = FillTarget(null, null, null, null)

fun findFillTarget(structure: Structure): FillTarget =
    structure.children.fold(emptyFillTarget, FillTarget::tryUpdate)
