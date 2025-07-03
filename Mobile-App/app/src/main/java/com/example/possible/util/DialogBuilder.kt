import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.Dialog
import android.content.Context
import android.view.View
import android.widget.TextView
import androidx.appcompat.widget.AppCompatButton
import androidx.recyclerview.widget.RecyclerView
import com.example.possible.R
import com.example.possible.model.Child
import com.example.possible.model.Question
import com.example.possible.model.Test
import com.example.possible.repo.local.SharedPref
import com.example.possible.util.adapter.SelectingAdapter
import com.google.android.material.textfield.TextInputEditText

object DialogBuilder {
    fun showAlertDialog(
        context: Context,
        message: String,
        title: String,
        positiveButton: String,
        negativeButton: String,
        onConfirm: () -> Unit,
        onCancel: () -> Unit,
    ) {
        val builder = AlertDialog.Builder(context)
        builder.setMessage(message)
        builder.setCancelable(true)
        builder.setTitle(title)

        builder.setPositiveButton(positiveButton) { dialog, _ ->
            onConfirm()
            dialog.dismiss()
        }
        builder.setNegativeButton(negativeButton) { dialog, _ ->
            onCancel()
            dialog.dismiss()

        }
        val dialog = builder.create()

        dialog.show()

    }

    fun showErrorDialog(
        context: Context,
        meesage:String,
        desision:String
    ){
        val errorDialog = Dialog(context)
        errorDialog.setContentView(R.layout.error_dialog)
        errorDialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        errorDialog.setCancelable(false)
        val btn = errorDialog.findViewById<AppCompatButton>(R.id.dialogTryAgainBtn)
        val message = errorDialog.findViewById<TextView>(R.id.message)
        message.text=meesage
        btn.text=desision
        btn.setOnClickListener {
            errorDialog.dismiss()
        }
        errorDialog.show()
    }
    @SuppressLint("SetTextI18n")
    fun showInternetConnectionDialog(context: Context,onEnd: () -> Unit){
        val errorDialog = Dialog(context)
        errorDialog.setContentView(R.layout.error_dialog)
        errorDialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        errorDialog.setCancelable(false)
        val btn = errorDialog.findViewById<AppCompatButton>(R.id.dialogTryAgainBtn)
        val message = errorDialog.findViewById<TextView>(R.id.message)
        message.text="No Internet Connection"
        btn.text="OK"
        btn.setOnClickListener {
            errorDialog.dismiss()
            onEnd()
        }
        errorDialog.show()
    }
    fun showSuccessDialog(
        context: Context,
        meesage:String,
        desision:String,
        onConfirm: () -> Unit
        ) {
        val successDialog = Dialog(context)
        successDialog.setContentView(R.layout.success_dialog)
        successDialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        successDialog.setCancelable(false)
        val btn = successDialog.findViewById<TextView>(R.id.dialogNext)
        val message = successDialog.findViewById<TextView>(R.id.message)
        message.text = meesage
        btn.text = desision
        btn.setOnClickListener {
            onConfirm()
            successDialog.dismiss()
        }
        successDialog.show()
    }

    fun showSelectChildrenDialog(context: Context, listOfChildren:List<Child>,
                                 testName:String, testType:String, questions:List<Question>,
                                 onConfirm: (test:Test) -> Unit){
        var finalSelectedItems = ArrayList<String>()
        val selectChildrenDialog = Dialog(context)
        selectChildrenDialog.setContentView(R.layout.select_children_dialog)
        selectChildrenDialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        selectChildrenDialog.setCancelable(true)
        val btn = selectChildrenDialog.findViewById<AppCompatButton>(R.id.sendBtn)
        val recyclerView = selectChildrenDialog.findViewById<RecyclerView>(R.id.selectingAdapter)
        val adapter = SelectingAdapter(listOfChildren as ArrayList<Child>)
        recyclerView.adapter = adapter
        btn.setOnClickListener {
            this.showAlertDialog(context,"Confirm sending the exam?","Confirm",
                "Confirm","Undo",onConfirm={
                    val selectedItems = adapter.getSelectedItems()
                    finalSelectedItems = selectedItems
                    if (selectedItems.isNotEmpty()) {
                        val test = Test(testName, testType, questions, finalSelectedItems)
                        onConfirm(test)
                    }
                    else{
                        showErrorDialog(context,"Please select at least one child","OK")
                    }
                },
                onCancel = {

                })
            // Get the selected items from the adapter

            selectChildrenDialog.dismiss()
        }
        selectChildrenDialog.show()
    }

    fun ipDialog(context: Context,onConfirm: (ip:String) -> Unit){
        val ipDialog = Dialog(context)
        ipDialog.setContentView(R.layout.add_ip_dialog)
        ipDialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        ipDialog.setCancelable(true)
        val btn = ipDialog.findViewById<AppCompatButton>(R.id.save)
        val ipEt = ipDialog.findViewById<TextInputEditText>(R.id.ipEt)
        ipEt.setText(SharedPref(context).getIp())
        btn.setOnClickListener {
            if (ipEt.text.toString().isEmpty()){
                showErrorDialog(context,"Please enter a valid IP","OK")
                return@setOnClickListener
            }
            onConfirm(ipEt.text.toString())
            ipDialog.dismiss()
        }
        ipDialog.show()


    }
}