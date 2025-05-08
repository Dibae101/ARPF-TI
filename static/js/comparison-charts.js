// Charts for the AI vs Manual Rules Comparison page
document.addEventListener('DOMContentLoaded', function() {
    // Colors
    const colors = {
        manual: {
            primary: 'rgb(37, 99, 235)',     // blue-600
            bg: 'rgba(59, 130, 246, 0.2)',   // blue-50
            border: 'rgb(37, 99, 235)'       // blue-600
        },
        ai: {
            primary: 'rgb(5, 150, 105)',     // green-600
            bg: 'rgba(16, 185, 129, 0.2)',   // green-50
            border: 'rgb(5, 150, 105)'       // green-600
        }
    };

    // Common chart options
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
            }
        }
    };

    // 1. Precision Rate Chart
    const precisionCtx = document.getElementById('precisionRateChart');
    if (precisionCtx) {
        const manualPrecision = parseFloat(precisionCtx.getAttribute('data-manual-precision') || 65.1);
        const aiPrecision = parseFloat(precisionCtx.getAttribute('data-ai-precision') || 86.8);
        
        new Chart(precisionCtx, {
            type: 'bar',
            data: {
                labels: ['Manual Rules', 'AI Rules'],
                datasets: [{
                    label: 'Precision Rate (%)',
                    data: [manualPrecision, aiPrecision],
                    backgroundColor: [colors.manual.bg, colors.ai.bg],
                    borderColor: [colors.manual.border, colors.ai.border],
                    borderWidth: 1
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }

    // 2. True Positives Chart
    const tpCtx = document.getElementById('truePositivesChart');
    if (tpCtx) {
        const manualTP = parseInt(tpCtx.getAttribute('data-manual-tp') || 177);
        const aiTP = parseInt(tpCtx.getAttribute('data-ai-tp') || 230);
        
        new Chart(tpCtx, {
            type: 'bar',
            data: {
                labels: ['Manual Rules', 'AI Rules'],
                datasets: [{
                    label: 'True Positives (Count)',
                    data: [manualTP, aiTP],
                    backgroundColor: [colors.manual.bg, colors.ai.bg],
                    borderColor: [colors.manual.border, colors.ai.border],
                    borderWidth: 1
                }]
            },
            options: chartOptions
        });
    }

    // 3. False Positives Chart
    const fpCtx = document.getElementById('falsePositivesChart');
    if (fpCtx) {
        const manualFP = parseInt(fpCtx.getAttribute('data-manual-fp') || 95);
        const aiFP = parseInt(fpCtx.getAttribute('data-ai-fp') || 35);
        
        new Chart(fpCtx, {
            type: 'bar',
            data: {
                labels: ['Manual Rules', 'AI Rules'],
                datasets: [{
                    label: 'False Positives (Count)',
                    data: [manualFP, aiFP],
                    backgroundColor: [colors.manual.bg, colors.ai.bg],
                    borderColor: [colors.manual.border, colors.ai.border],
                    borderWidth: 1
                }]
            },
            options: chartOptions
        });
    }

    // 4. Response Time Chart
    const rtCtx = document.getElementById('responseTimeChart');
    if (rtCtx) {
        // Default values if not provided
        const manualRT = 12.5;
        const aiRT = 3.8;
        
        new Chart(rtCtx, {
            type: 'bar',
            data: {
                labels: ['Manual Rules', 'AI Rules'],
                datasets: [{
                    label: 'Response Time (minutes)',
                    data: [manualRT, aiRT],
                    backgroundColor: [colors.manual.bg, colors.ai.bg],
                    borderColor: [colors.manual.border, colors.ai.border],
                    borderWidth: 1
                }]
            },
            options: chartOptions
        });
    }

    // 5. Rule Matches Chart
    const rmCtx = document.getElementById('ruleMatchesChart');
    if (rmCtx) {
        // Default values if not provided
        const manualRM = 272;
        const aiRM = 265;
        
        new Chart(rmCtx, {
            type: 'bar',
            data: {
                labels: ['Manual Rules', 'AI Rules'],
                datasets: [{
                    label: 'Rule Matches (Count)',
                    data: [manualRM, aiRM],
                    backgroundColor: [colors.manual.bg, colors.ai.bg],
                    borderColor: [colors.manual.border, colors.ai.border],
                    borderWidth: 1
                }]
            },
            options: chartOptions
        });
    }
    
    // 6. Security Mitigation Chart
    const smCtx = document.getElementById('securityMitigationChart');
    if (smCtx) {
        // Mock data for attack types
        const attackTypes = ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion', 'Command Injection'];
        const attackCounts = [42, 35, 28, 21, 16];
        
        new Chart(smCtx, {
            type: 'pie',
            data: {
                labels: attackTypes,
                datasets: [{
                    data: attackCounts,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    }
                }
            }
        });
    }
    
    // 7. Security Risk Trend Chart
    const srtCtx = document.getElementById('securityRiskTrendChart');
    if (srtCtx) {
        // Mock data for security risk trend
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];
        const manualData = [65, 72, 68, 75, 79, 82];
        const aiData = [70, 78, 82, 89, 92, 95];
        
        new Chart(srtCtx, {
            type: 'line',
            data: {
                labels: months,
                datasets: [
                    {
                        label: 'Manual Rules',
                        data: manualData,
                        borderColor: colors.manual.primary,
                        backgroundColor: 'transparent',
                        tension: 0.4,
                        borderWidth: 2
                    },
                    {
                        label: 'AI Rules',
                        data: aiData,
                        borderColor: colors.ai.primary,
                        backgroundColor: 'transparent',
                        tension: 0.4,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        min: 50,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Risk Mitigation %'
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // 8. Attack Type Comparison Chart
    const atcCtx = document.getElementById('attackTypeComparisonChart');
    if (atcCtx) {
        // Mock data for attack type comparison
        const attackCategories = ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion', 'Command Injection'];
        const manualEffectiveness = [75, 68, 82, 62, 58];
        const aiEffectiveness = [92, 88, 85, 90, 95];
        
        new Chart(atcCtx, {
            type: 'radar',
            data: {
                labels: attackCategories,
                datasets: [
                    {
                        label: 'Manual Rules',
                        data: manualEffectiveness,
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        borderColor: 'rgb(54, 162, 235)',
                        pointBackgroundColor: 'rgb(54, 162, 235)',
                        pointBorderColor: '#fff',
                        pointRadius: 5
                    },
                    {
                        label: 'AI Rules',
                        data: aiEffectiveness,
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgb(75, 192, 192)',
                        pointBackgroundColor: 'rgb(75, 192, 192)',
                        pointBorderColor: '#fff',
                        pointRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: {
                            display: true
                        },
                        suggestedMin: 50,
                        suggestedMax: 100
                    }
                }
            }
        });
    }
    
    // 9. AI Advantage Chart
    const aaCtx = document.getElementById('aiAdvantageChart');
    if (aaCtx) {
        // Mock data for AI advantage
        const attackTypes = ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion', 'Command Injection'];
        const advantages = [17, 20, 3, 28, 37]; // AI effectiveness - Manual effectiveness
        
        new Chart(aaCtx, {
            type: 'bar',
            data: {
                labels: attackTypes,
                datasets: [{
                    label: 'AI Advantage (%)',
                    data: advantages,
                    backgroundColor: 'rgba(153, 102, 255, 0.7)',
                    borderColor: 'rgb(153, 102, 255)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Percentage Points'
                        }
                    }
                }
            }
        });
    }
    
    // 10. Detection Time Comparison Chart
    const dtcCtx = document.getElementById('detectionTimeComparisonChart');
    if (dtcCtx) {
        // Attack types for detection time comparison
        const attackTypes = ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion', 'Command Injection'];
        
        // Average detection time in minutes for each attack type
        const manualDetectionTimes = [15.2, 12.7, 11.5, 18.3, 14.1];
        const aiDetectionTimes = [4.3, 3.6, 5.8, 3.2, 2.9];
        
        new Chart(dtcCtx, {
            type: 'bar',
            data: {
                labels: attackTypes,
                datasets: [
                    {
                        label: 'Manual Rules (minutes)',
                        data: manualDetectionTimes,
                        backgroundColor: colors.manual.bg,
                        borderColor: colors.manual.border,
                        borderWidth: 1
                    },
                    {
                        label: 'AI Rules (minutes)',
                        data: aiDetectionTimes,
                        backgroundColor: colors.ai.bg,
                        borderColor: colors.ai.border,
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label.replace(' (minutes)', '') + ': ' + context.raw + ' minutes';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Detection Time (minutes)'
                        }
                    }
                }
            }
        });
    }

    // Add refresh button functionality
    const refreshButton = document.getElementById('refresh-comparison');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            location.reload();
        });
    }
    
    // Add continue iteration checkbox functionality
    const continueIterationCheckbox = document.getElementById('continue_iteration');
    if (continueIterationCheckbox) {
        continueIterationCheckbox.addEventListener('change', function() {
            // This would typically update some backend setting via AJAX
            console.log("Continue iteration setting changed:", this.checked);
        });
    }
    
    // 11. Matrix Comparison Chart
    const matrixCtx = document.getElementById('matrixComparisonChart');
    if (matrixCtx) {
        // Get data from data attributes
        const manualPrecision = parseFloat(matrixCtx.getAttribute('data-manual-precision') || 65.1);
        const aiPrecision = parseFloat(matrixCtx.getAttribute('data-ai-precision') || 86.8);
        const manualFP = parseInt(matrixCtx.getAttribute('data-manual-fp') || 95);
        const aiFP = parseInt(matrixCtx.getAttribute('data-ai-fp') || 35);
        
        // Create a scatter plot for matrix comparison
        new Chart(matrixCtx, {
            type: 'scatter',
            data: {
                datasets: [
                    {
                        label: 'Manual Rules',
                        data: [{
                            x: manualFP,
                            y: manualPrecision
                        }],
                        backgroundColor: colors.manual.primary,
                        borderColor: colors.manual.border,
                        borderWidth: 2,
                        pointRadius: 10,
                        pointHoverRadius: 12
                    },
                    {
                        label: 'AI Rules',
                        data: [{
                            x: aiFP,
                            y: aiPrecision
                        }],
                        backgroundColor: colors.ai.primary,
                        borderColor: colors.ai.border,
                        borderWidth: 2,
                        pointRadius: 10,
                        pointHoverRadius: 12
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'False Positives (Count)',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        suggestedMin: 0,
                        suggestedMax: Math.max(manualFP, aiFP) * 1.2
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Precision (%)',
                            font: {
                                size: 14,
                                weight: 'bold'
                            }
                        },
                        suggestedMin: Math.min(manualPrecision, aiPrecision) * 0.8,
                        suggestedMax: 100
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.dataset.label;
                                const x = context.parsed.x;
                                const y = context.parsed.y;
                                return `${label}: ${y}% precision, ${x} false positives`;
                            }
                        }
                    },
                    annotation: {
                        annotations: {
                            line1: {
                                type: 'line',
                                xMin: 0,
                                xMax: Math.max(manualFP, aiFP) * 1.2,
                                yMin: 80,
                                yMax: 80,
                                borderColor: 'rgba(0, 200, 0, 0.3)',
                                borderWidth: 2,
                                borderDash: [6, 6],
                                label: {
                                    content: 'Good Precision (80%+)',
                                    enabled: true,
                                    position: 'start'
                                }
                            }
                        }
                    }
                }
            }
        });
    }
});