package l.keepassa.autofill

import android.os.CancellationSignal
import android.service.autofill.*
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

class AutofillCredentialsService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return
        val target = findFillTarget(Structure(structure))
        if (target.usernameField == null && target.passwordField == null) {
            callback.onSuccess(null)
            return
        }

        val datasetBuilder = Dataset.Builder()
        if (target.usernameField != null) {
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1)
            presentation.setTextViewText(android.R.id.text1, "MyTestUsername")
            datasetBuilder.setValue(
                target.usernameField.autofillId!!,
                AutofillValue.forText("TestUsername"),
                presentation
            )
        }

        if (target.passwordField != null) {
            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1)
            presentation.setTextViewText(android.R.id.text1, "MyTestPassword")
            datasetBuilder.setValue(
                target.passwordField.autofillId!!,
                AutofillValue.forText("TestPassword"),
                presentation
            )
        }

        callback.onSuccess(
            FillResponse.Builder()
                .addDataset(datasetBuilder.build())
                .build()
        )
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // TODO
    }

}
