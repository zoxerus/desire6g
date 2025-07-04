document.getElementById('fileInput').addEventListener('change', handleFileSelect, false);

function handleFileSelect(evt) {
    var file = evt.target.files[0];
    console.log(file);
    var reader = new FileReader();

    reader.onload = function(e) {
        try {
            var topologyData = JSON.parse(e.target.result);
            loadTopology(topologyData);
        } catch (error) {
            alert('Error parsing file: ' + error.message);
        }
    };

    reader.readAsText(file);
}

function loadTopology(topologyData) {
    var cy = cytoscape({
        container: document.getElementById('cy'),
        elements: topologyData,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'background-image': 'data(icon)', // Dynamically get icon path.
                    'background-fit': 'cover', // Resize image to fit node.
                    'width': 50, // Set node width.
                    'height': 50 // Set node height.
                }
            },
            {
                selector: 'edge',
                style: {
                    'curve-style': 'bezier'
                }
            }
        ],
        layout: {
            name: 'cose' // Example layout.
        }
    });

    cy.on('tap', 'node', function(evt) {
        var node = evt.target;
        document.getElementById('nodeInfoPre').innerHTML =  JSON.stringify(node.data(), null, 2); //Prettify the JSON output.
    });
}