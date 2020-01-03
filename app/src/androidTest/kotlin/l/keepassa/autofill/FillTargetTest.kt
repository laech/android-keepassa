package l.keepassa.autofill

import android.view.View.AUTOFILL_HINT_PASSWORD
import android.view.View.AUTOFILL_HINT_USERNAME
import org.junit.Assert.assertEquals
import org.junit.Test

class FillTargetTest {

    @Test
    fun findsPackageIdFromWindowTitleIfNoViewHasPackageId() {
        val result = findFillTarget(
            Structure(
                sequenceOf(
                    Structure.Window(
                        "my.package.id/my.package.id.MainActivity", sequenceOf(
                            emptyTextField,
                            emptyTextField
                        )
                    )
                )
            )
        )
        assertEquals(emptyFillTarget.copy(packageId = "my.package.id"), result)
    }

    @Test
    fun findsPackageIdFromView() {
        val result = findFillTarget(
            Structure(
                sequenceOf(
                    Structure.Window(
                        "my.package.id/my.package.id.MainActivity", sequenceOf(
                            emptyTextField,
                            emptyTextField.copy(packageId = "my.true.package.id")
                        )
                    )
                )
            )
        )
        assertEquals(emptyFillTarget.copy(packageId = "my.true.package.id"), result)
    }

    @Test
    fun findsFields() {
        val usernameField = emptyTextField.copy(autofillHints = listOf(AUTOFILL_HINT_USERNAME))
        val passwordField = emptyTextField.copy(autofillHints = listOf(AUTOFILL_HINT_PASSWORD))
        val result = findFillTarget(
            Structure(
                sequenceOf(
                    Structure.Window(null, sequenceOf(usernameField, passwordField))
                )
            )
        )
        assertEquals(
            emptyFillTarget.copy(
                usernameField = usernameField,
                passwordField = passwordField
            ),
            result
        )
    }
}
