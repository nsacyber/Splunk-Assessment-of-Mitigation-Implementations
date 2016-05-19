require([
      'splunkjs/mvc/simplexml/ready!',
      "splunkjs/mvc"
  ],
  function(mvc) {
    // Get the default model
    var defaultTokenModel = splunkjs.mvc.Components.getInstance("default");

    // Set the default hostStatusTime values based on 'time1'
    defaultTokenModel.set({
      "hostStatusTime.earliest": defaultTokenModel.get("time1.earliest"),
      "hostStatusTime.latest": defaultTokenModel.get("time1.latest")
    });
    // If 'time1' changes, update hostStatusTime accordingly.
    defaultTokenModel.on("change:time1.earliest change:time1.latest", function(model, value) {
      defaultTokenModel.set({
        "hostStatusTime.earliest": defaultTokenModel.get("time1.earliest"),
        "hostStatusTime.latest": defaultTokenModel.get("time1.latest")
      });
    });

    // Set the default values for the 'status' token
    defaultTokenModel.set("status", "missing - *");

    // Get the yesterday's date (because data is collected nightly), format to "YY-MM-DD", and set 'time' token
    var today = new Date();
    var yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);
    var formattedDate = String(yesterday.getFullYear()).substr(2) + "-" + (yesterday.getMonth() < 9 ? "0" : "") + (yesterday.getMonth() + 1) + "-" + (yesterday.getDate() < 10 ? "0" : "") + yesterday.getDate();
    defaultTokenModel.set("time",formattedDate);
});