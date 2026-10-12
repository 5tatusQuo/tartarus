// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

public class TartarusStrings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DataIterator values = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        while (values.hasNext() && count++ < 5000) {
            Data value = values.next();
            if (value.hasStringValue()) {
                String text = value.getDefaultValueRepresentation().replace("\t", " ").replace("\n", "\\n");
                text = text.substring(0, Math.min(text.length(), 512));
                println(value.getAddress() + "\t" + text);
            }
        }
    }
}
