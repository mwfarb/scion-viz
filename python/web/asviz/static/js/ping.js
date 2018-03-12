/*
 * Initializes ping topology chart. TODO (mwfarb): Chart is a placeholder test
 * with no real data. Based on nvd3 comminity's real time chart at
 * github.com/novus/nvd3/blob/master/test/realTimeChartTest.html
 */
function drawPing(div_id, width, height, dst) {
    var chart;
    var run = false;
    var maxXValues = 60;
    var now = Date.now();
    var data = [ {
        key : dst + " response",
        color : "orange",
    } ];

    nv.addGraph(function() {

        chart = nv.models.historicalBarChart().padData(true)
        // chart = nv.models.multiBarChart()// would allow for stacked icmp/scmp

        chart.x(function(d, i) {
            return d.x
        });

        chart.xAxis.axisLabel("Time").tickFormat(function(d) {
            var date = new Date(d);
            if (date.getSeconds() == 0) {
                return d3.time.format('%H:%M')(new Date(d))
            } else {
                return d3.time.format(':%S')(new Date(d))
            }
        })

        chart.yAxis.axisLabel('Response (ms)').tickFormat(d3.format(',.1f'));
        chart.forceY([ 0, 10 ])

        chart.tooltip.keyFormatter(function(d) {
            return d3.time.format('%H:%M:%S')(new Date(d))
        });

        chart.showXAxis(true).showYAxis(true).rightAlignYAxis(true).margin({
            right : 90
        });

        data[0].values = []
        // pre-fill with empty data for scroll
        for (var i = 0; i < maxXValues; i++) {
            data[0].values.push({
                x : now - (1000 * i),
                y : null
            });
        }
        // TODO (mwfarb): pre-fill creates a squashing effect

        d3.select("#" + div_id).append('svg').datum(data).transition()
                .duration(0).call(chart);

        nv.utils.windowResize(chart.update);

        return chart;
    });

    setInterval(function() {
        // load with random data points for examples
        data[0].values.push({
            x : Date.now(),
            y : run ? Math.random() * 10.0 : null
        });

        while (data[0].values.length > maxXValues) {
            data[0].values.shift();
        }

        chart.update();
    }, 1000);

    d3.select("#start-stop-ping-button").on("click", function() {
        run = !run;
    });

    // load topology file for sample AS Addresses
    console.log(JSON.stringify(resTopoFile));
    $("#pingSelect").append(new Option());
    if (resTopoFile != undefined) {
        for ( var br in resTopoFile.BorderRouters) {
            for ( var _if in resTopoFile.BorderRouters[br].Interfaces) {
                var ia = resTopoFile.BorderRouters[br].Interfaces[_if];
                $("#pingSelect").append(new Option(ia.ISD_AS, ia.Remote.Addr));
            }
        }
    }
}

function pingFill() {
    var selectedAs = $('#pingSelect :selected').text();
    var selectedAddr = $('#pingSelect :selected').val();
    console.log("selected ping: " + selectedAs + "," + selectedAddr)
    $("#dst_ping").val(selectedAs);
    $("#dst_addr_ping").val(selectedAddr);
}
