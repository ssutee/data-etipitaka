var app = angular.module('EtipitakaUserDataApp', [
  'ui.bootstrap', 'ngFileUpload'
]);

app.run(function($rootScope, $http) {
    $rootScope.items = [];
    $rootScope.sharingList = [];
    $rootScope.sharing = {}
    $rootScope.loadUserData = function() {
        $http.get('/user_data_list/').then(function(response) {
            $rootScope.items = eval(response.data.items);
        }, function(error) {
            $rootScope.items = [];
        });
    };

    $rootScope.loadSharingList = function() {
        $http.get('/sharing_list/').then(function(response) {
            $rootScope.sharingList = eval(response.data.items);
            for (var i=0; i < $rootScope.sharingList.length; i++) {
                $rootScope.sharing[$rootScope.sharingList[i].pk] = $rootScope.sharingList[i].sharing != 0;
            }
         }, function(error) {
            $rootScope.sharingList = [];
        });
    }
});

app.config(['$interpolateProvider', function ($interpolateProvider) {
    $interpolateProvider.startSymbol('<[');
    $interpolateProvider.endSymbol(']>');
}]);  

app.controller('UserDataController', function($scope, $rootScope, $uibModal, $http) {
    $scope.sharing ={};

    $scope.upload = function() {
        var modalInstance = $uibModal.open({
            animation: true,
            templateUrl: 'uploadModalContent.html',
            controller: 'UploadModalInstanceCtrl'
        });
    };

    $scope.init = function() {
        $rootScope.loadUserData();
        $rootScope.loadSharingList();
    };

    $scope.ios = function(element) {
        return element.fields.platform == 'ios';
    };

    $scope.android = function(element) {
        return element.fields.platform == 'android';
    };

    $scope.pc = function(element) {
        return element.fields.platform == 'pc';
    };

    $scope.formatDate = function(date) {
        return moment(date).format('YYYY-MM-D hh:mm:ss');
    };

    var doDelete = function(pk, csrfToken) {
        $http({url:'/user_data/'+pk+'/', 
              method: 'DELETE', 
              headers: {'X-CSRFToken': csrfToken}})              
        .then(function(response) {
            $rootScope.loadUserData();
        }, function(error) {
            console.log(error);
        });
    };

    $scope.delete = function(pk, csrfToken) {
        bootbox.confirm("Are you sure?", function(result) {
            if (result) {
                doDelete(pk, csrfToken);
            }
        }); 
    };

    $scope.changeSharing = function(pk, csrfToken) {        
        $http({url:'/follower/'+pk+'/', 
              method: ($rootScope.sharing[pk] ? 'POST' : 'DELETE') , 
              headers: {'X-CSRFToken': csrfToken}})              
        .then(function(response) {            
        }, function(error) {
            console.log(error);
        });
    }
});

app.controller('RegisterController', function($scope, $http, $uibModal, $timeout, $window) {
    $scope.inputForm = {};
    $scope.error = {};
    
    var modalInstance = null;

    var openLoadingModal = function() {
        return $uibModal.open(
            {templateUrl:'loadingModalContent.html',
             controller: 'LoadingModalInstanceCtrl',
             size: 'sm',
             keyboard: false,
             backdrop: false});
    };

    var checkMatchPassword = function() {
        return $scope.inputForm.password1 == $scope.inputForm.password2;
    };

    var checkLongPassword = function() {
        return $scope.inputForm.password1.length > 4;
    };

    var checkFillInputs = function() {
        return $scope.inputForm.email && $scope.inputForm.username && 
            $scope.inputForm.password1 && $scope.inputForm.password2;
    };

    var doSignup = function(url) {
        $http.post(url, $scope.inputForm).then(function(response){
                console.log(response);
                modalInstance.close();
                $window.location.href = '/signup/validate/';
            }, function(error) {
                console.log(error);
                modalInstance.close();
                if (error.data.email) {
                    $scope.error.email = error.data.email[0];
                }
                if (error.data.username) {
                    $scope.error.username = error.data.username[0];
                }
            });
    };

    $scope.signup = function(url) {
        $scope.error = {};
        if (checkFillInputs()) {
            if (checkMatchPassword() && checkLongPassword()) {
                modalInstance = openLoadingModal();
                $timeout(function() {
                    doSignup(url);
                }, 100);                
            } else if (checkMatchPassword()) {
                $scope.error.password = 'password is too short';
            } else {
                $scope.error.password = 'passwords not match';
            }            
        }
    };

});

app.controller('UploadModalInstanceCtrl', function($scope, $rootScope, $uibModalInstance, $window, Upload) {
    $scope.uploadFiles = function(file, errFiles, csrfToken) {
        console.log(file);
        $scope.f = file;
        $scope.progress = 0;
        $scope.success = false;
        $scope.fileExists = false;
        if (file) {
            console.log(file.name);
            file.upload = Upload.upload({
                url: '/upload/',
                data: {file: file, title: file.name, csrfmiddlewaretoken: csrfToken}
            });
            file.upload.then(function(response) {
                if (response.data.success) {
                    $scope.success = true;
                    $rootScope.loadUserData()
                } else if (response.data.file_exists) {
                    $scope.fileExists = true;
                }
            }, function(error) {
            }, function(evt) {
                $scope.progress = Math.min(100, parseInt(100.0 * evt.loaded / evt.total));
            });
        }
    };

    $scope.close = function() {
        $uibModalInstance.close();
    };
});

app.controller('LoadingModalInstanceCtrl', function($scope, $rootScope, $uibModalInstance) {
    $scope.close = function() {
        $uibModalInstance.close();
    };    
});

