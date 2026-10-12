// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

public class TartarusStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DataIterator values = currentProgram.getListing().getDefinedData(true);
        while (values.hasNext()) {
            Data value = values.next();
            if (value.hasStringValue()) {
                String text = value.getDefaultValueRepresentation().replace("\t", " ").replace("\n", "\\n");
                println(value.getAddress() + "\t" + text);
            }
        }
    }
}
